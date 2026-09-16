rule TTP_XOR_WriteProcessMemory_3d84 {
  strings:
    $key_3d84 = { 6a f6 [2] 58 d4 [2] 5e e1 [2] 70 e1 [2] 4f fd }

  condition:
    any of them
}