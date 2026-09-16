rule TTP_XOR_WriteProcessMemory_5ee6 {
  strings:
    $key_5ee6 = { 09 94 [2] 3b b6 [2] 3d 83 [2] 13 83 [2] 2c 9f }

  condition:
    any of them
}