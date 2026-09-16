rule TTP_XOR_WriteProcessMemory_1584 {
  strings:
    $key_1584 = { 42 f6 [2] 70 d4 [2] 76 e1 [2] 58 e1 [2] 67 fd }

  condition:
    any of them
}