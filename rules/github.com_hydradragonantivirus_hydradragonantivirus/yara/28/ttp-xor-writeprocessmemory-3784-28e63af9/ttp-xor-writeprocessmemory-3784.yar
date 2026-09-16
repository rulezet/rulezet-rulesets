rule TTP_XOR_WriteProcessMemory_3784 {
  strings:
    $key_3784 = { 60 f6 [2] 52 d4 [2] 54 e1 [2] 7a e1 [2] 45 fd }

  condition:
    any of them
}