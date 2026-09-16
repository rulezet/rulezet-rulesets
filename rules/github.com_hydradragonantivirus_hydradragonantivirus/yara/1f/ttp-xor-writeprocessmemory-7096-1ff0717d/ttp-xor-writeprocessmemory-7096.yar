rule TTP_XOR_WriteProcessMemory_7096 {
  strings:
    $key_7096 = { 27 e4 [2] 15 c6 [2] 13 f3 [2] 3d f3 [2] 02 ef }

  condition:
    any of them
}