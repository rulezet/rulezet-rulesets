rule TTP_XOR_WriteProcessMemory_1f84 {
  strings:
    $key_1f84 = { 48 f6 [2] 7a d4 [2] 7c e1 [2] 52 e1 [2] 6d fd }

  condition:
    any of them
}