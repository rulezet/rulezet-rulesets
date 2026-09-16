rule TTP_XOR_WriteProcessMemory_4a22 {
  strings:
    $key_4a22 = { 1d 50 [2] 2f 72 [2] 29 47 [2] 07 47 [2] 38 5b }

  condition:
    any of them
}