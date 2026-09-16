rule TTP_XOR_WriteProcessMemory_7242 {
  strings:
    $key_7242 = { 25 30 [2] 17 12 [2] 11 27 [2] 3f 27 [2] 00 3b }

  condition:
    any of them
}