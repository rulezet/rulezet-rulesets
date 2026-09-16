rule TTP_XOR_WriteProcessMemory_58b0 {
  strings:
    $key_58b0 = { 0f c2 [2] 3d e0 [2] 3b d5 [2] 15 d5 [2] 2a c9 }

  condition:
    any of them
}