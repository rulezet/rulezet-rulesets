rule TTP_XOR_WriteProcessMemory_1ae7 {
  strings:
    $key_1ae7 = { 4d 95 [2] 7f b7 [2] 79 82 [2] 57 82 [2] 68 9e }

  condition:
    any of them
}