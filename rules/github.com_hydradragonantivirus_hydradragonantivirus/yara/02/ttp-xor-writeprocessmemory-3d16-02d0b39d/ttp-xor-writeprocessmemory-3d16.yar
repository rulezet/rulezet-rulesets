rule TTP_XOR_WriteProcessMemory_3d16 {
  strings:
    $key_3d16 = { 6a 64 [2] 58 46 [2] 5e 73 [2] 70 73 [2] 4f 6f }

  condition:
    any of them
}