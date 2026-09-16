rule TTP_XOR_WriteProcessMemory_3d66 {
  strings:
    $key_3d66 = { 6a 14 [2] 58 36 [2] 5e 03 [2] 70 03 [2] 4f 1f }

  condition:
    any of them
}