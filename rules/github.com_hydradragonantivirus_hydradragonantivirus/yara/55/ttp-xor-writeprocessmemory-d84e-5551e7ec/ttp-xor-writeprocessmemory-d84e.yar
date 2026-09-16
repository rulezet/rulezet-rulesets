rule TTP_XOR_WriteProcessMemory_d84e {
  strings:
    $key_d84e = { 8f 3c [2] bd 1e [2] bb 2b [2] 95 2b [2] aa 37 }

  condition:
    any of them
}