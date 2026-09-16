rule TTP_XOR_WriteProcessMemory_1a22 {
  strings:
    $key_1a22 = { 4d 50 [2] 7f 72 [2] 79 47 [2] 57 47 [2] 68 5b }

  condition:
    any of them
}