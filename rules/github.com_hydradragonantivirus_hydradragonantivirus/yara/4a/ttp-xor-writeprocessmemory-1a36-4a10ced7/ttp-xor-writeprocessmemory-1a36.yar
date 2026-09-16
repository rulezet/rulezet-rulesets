rule TTP_XOR_WriteProcessMemory_1a36 {
  strings:
    $key_1a36 = { 4d 44 [2] 7f 66 [2] 79 53 [2] 57 53 [2] 68 4f }

  condition:
    any of them
}