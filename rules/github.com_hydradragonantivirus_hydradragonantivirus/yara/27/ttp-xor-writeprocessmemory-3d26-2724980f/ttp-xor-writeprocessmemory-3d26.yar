rule TTP_XOR_WriteProcessMemory_3d26 {
  strings:
    $key_3d26 = { 6a 54 [2] 58 76 [2] 5e 43 [2] 70 43 [2] 4f 5f }

  condition:
    any of them
}