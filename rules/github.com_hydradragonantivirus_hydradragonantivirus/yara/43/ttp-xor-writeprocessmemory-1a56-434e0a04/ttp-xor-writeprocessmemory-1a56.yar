rule TTP_XOR_WriteProcessMemory_1a56 {
  strings:
    $key_1a56 = { 4d 24 [2] 7f 06 [2] 79 33 [2] 57 33 [2] 68 2f }

  condition:
    any of them
}