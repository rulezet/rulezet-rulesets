rule TTP_XOR_WriteProcessMemory_3384 {
  strings:
    $key_3384 = { 64 f6 [2] 56 d4 [2] 50 e1 [2] 7e e1 [2] 41 fd }

  condition:
    any of them
}