rule TTP_XOR_WriteProcessMemory_5584 {
  strings:
    $key_5584 = { 02 f6 [2] 30 d4 [2] 36 e1 [2] 18 e1 [2] 27 fd }

  condition:
    any of them
}