rule TTP_XOR_WriteProcessMemory_0584 {
  strings:
    $key_0584 = { 52 f6 [2] 60 d4 [2] 66 e1 [2] 48 e1 [2] 77 fd }

  condition:
    any of them
}