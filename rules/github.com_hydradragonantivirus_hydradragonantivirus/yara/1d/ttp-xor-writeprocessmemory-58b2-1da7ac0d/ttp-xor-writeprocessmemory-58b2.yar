rule TTP_XOR_WriteProcessMemory_58b2 {
  strings:
    $key_58b2 = { 0f c0 [2] 3d e2 [2] 3b d7 [2] 15 d7 [2] 2a cb }

  condition:
    any of them
}