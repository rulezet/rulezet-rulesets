rule TTP_XOR_WriteProcessMemory_4f46 {
  strings:
    $key_4f46 = { 18 34 [2] 2a 16 [2] 2c 23 [2] 02 23 [2] 3d 3f }

  condition:
    any of them
}