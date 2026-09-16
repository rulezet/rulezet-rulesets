rule TTP_XOR_WriteProcessMemory_7084 {
  strings:
    $key_7084 = { 27 f6 [2] 15 d4 [2] 13 e1 [2] 3d e1 [2] 02 fd }

  condition:
    any of them
}