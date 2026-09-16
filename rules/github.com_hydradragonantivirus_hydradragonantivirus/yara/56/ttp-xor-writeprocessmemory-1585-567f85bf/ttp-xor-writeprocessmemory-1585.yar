rule TTP_XOR_WriteProcessMemory_1585 {
  strings:
    $key_1585 = { 42 f7 [2] 70 d5 [2] 76 e0 [2] 58 e0 [2] 67 fc }

  condition:
    any of them
}