rule TTP_XOR_WriteProcessMemory_67b4 {
  strings:
    $key_67b4 = { 30 c6 [2] 02 e4 [2] 04 d1 [2] 2a d1 [2] 15 cd }

  condition:
    any of them
}