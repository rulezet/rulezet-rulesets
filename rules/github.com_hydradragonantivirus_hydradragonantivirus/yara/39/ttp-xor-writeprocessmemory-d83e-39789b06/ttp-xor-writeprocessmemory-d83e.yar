rule TTP_XOR_WriteProcessMemory_d83e {
  strings:
    $key_d83e = { 8f 4c [2] bd 6e [2] bb 5b [2] 95 5b [2] aa 47 }

  condition:
    any of them
}