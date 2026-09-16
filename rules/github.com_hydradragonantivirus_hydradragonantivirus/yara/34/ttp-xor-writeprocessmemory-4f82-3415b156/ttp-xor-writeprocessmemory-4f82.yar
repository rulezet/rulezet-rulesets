rule TTP_XOR_WriteProcessMemory_4f82 {
  strings:
    $key_4f82 = { 18 f0 [2] 2a d2 [2] 2c e7 [2] 02 e7 [2] 3d fb }

  condition:
    any of them
}