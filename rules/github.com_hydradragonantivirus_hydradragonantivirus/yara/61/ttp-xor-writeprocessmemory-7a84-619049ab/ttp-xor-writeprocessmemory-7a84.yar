rule TTP_XOR_WriteProcessMemory_7a84 {
  strings:
    $key_7a84 = { 2d f6 [2] 1f d4 [2] 19 e1 [2] 37 e1 [2] 08 fd }

  condition:
    any of them
}