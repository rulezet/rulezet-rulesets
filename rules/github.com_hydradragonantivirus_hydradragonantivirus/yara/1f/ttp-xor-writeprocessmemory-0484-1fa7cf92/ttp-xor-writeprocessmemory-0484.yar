rule TTP_XOR_WriteProcessMemory_0484 {
  strings:
    $key_0484 = { 53 f6 [2] 61 d4 [2] 67 e1 [2] 49 e1 [2] 76 fd }

  condition:
    any of them
}