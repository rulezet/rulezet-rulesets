rule TTP_XOR_WriteProcessMemory_1a21 {
  strings:
    $key_1a21 = { 4d 53 [2] 7f 71 [2] 79 44 [2] 57 44 [2] 68 58 }

  condition:
    any of them
}