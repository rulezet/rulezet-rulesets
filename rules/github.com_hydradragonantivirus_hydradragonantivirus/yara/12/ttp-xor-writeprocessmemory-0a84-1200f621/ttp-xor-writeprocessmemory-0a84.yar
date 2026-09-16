rule TTP_XOR_WriteProcessMemory_0a84 {
  strings:
    $key_0a84 = { 5d f6 [2] 6f d4 [2] 69 e1 [2] 47 e1 [2] 78 fd }

  condition:
    any of them
}