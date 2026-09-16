rule TTP_XOR_WriteProcessMemory_5e84 {
  strings:
    $key_5e84 = { 09 f6 [2] 3b d4 [2] 3d e1 [2] 13 e1 [2] 2c fd }

  condition:
    any of them
}