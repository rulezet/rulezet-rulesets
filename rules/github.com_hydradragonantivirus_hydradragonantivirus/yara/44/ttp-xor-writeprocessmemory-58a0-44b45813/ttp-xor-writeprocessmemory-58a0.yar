rule TTP_XOR_WriteProcessMemory_58a0 {
  strings:
    $key_58a0 = { 0f d2 [2] 3d f0 [2] 3b c5 [2] 15 c5 [2] 2a d9 }

  condition:
    any of them
}