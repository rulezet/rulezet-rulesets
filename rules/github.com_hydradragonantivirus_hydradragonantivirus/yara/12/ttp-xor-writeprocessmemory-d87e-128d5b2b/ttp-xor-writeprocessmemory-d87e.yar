rule TTP_XOR_WriteProcessMemory_d87e {
  strings:
    $key_d87e = { 8f 0c [2] bd 2e [2] bb 1b [2] 95 1b [2] aa 07 }

  condition:
    any of them
}