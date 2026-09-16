rule TTP_XOR_WriteProcessMemory_6584 {
  strings:
    $key_6584 = { 32 f6 [2] 00 d4 [2] 06 e1 [2] 28 e1 [2] 17 fd }

  condition:
    any of them
}