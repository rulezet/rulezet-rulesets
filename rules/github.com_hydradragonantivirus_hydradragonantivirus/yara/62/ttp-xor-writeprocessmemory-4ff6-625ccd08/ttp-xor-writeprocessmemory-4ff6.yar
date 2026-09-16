rule TTP_XOR_WriteProcessMemory_4ff6 {
  strings:
    $key_4ff6 = { 18 84 [2] 2a a6 [2] 2c 93 [2] 02 93 [2] 3d 8f }

  condition:
    any of them
}