rule TTP_XOR_WriteProcessMemory_0184 {
  strings:
    $key_0184 = { 56 f6 [2] 64 d4 [2] 62 e1 [2] 4c e1 [2] 73 fd }

  condition:
    any of them
}