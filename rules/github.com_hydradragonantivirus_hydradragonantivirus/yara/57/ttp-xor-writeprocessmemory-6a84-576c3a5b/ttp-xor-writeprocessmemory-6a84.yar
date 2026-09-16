rule TTP_XOR_WriteProcessMemory_6a84 {
  strings:
    $key_6a84 = { 3d f6 [2] 0f d4 [2] 09 e1 [2] 27 e1 [2] 18 fd }

  condition:
    any of them
}