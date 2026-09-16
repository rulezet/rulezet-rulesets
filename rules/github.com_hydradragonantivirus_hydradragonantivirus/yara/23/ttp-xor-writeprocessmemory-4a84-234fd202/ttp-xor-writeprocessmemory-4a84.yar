rule TTP_XOR_WriteProcessMemory_4a84 {
  strings:
    $key_4a84 = { 1d f6 [2] 2f d4 [2] 29 e1 [2] 07 e1 [2] 38 fd }

  condition:
    any of them
}