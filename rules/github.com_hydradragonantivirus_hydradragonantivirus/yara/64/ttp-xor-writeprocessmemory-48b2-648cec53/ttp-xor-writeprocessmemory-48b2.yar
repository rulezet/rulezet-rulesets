rule TTP_XOR_WriteProcessMemory_48b2 {
  strings:
    $key_48b2 = { 1f c0 [2] 2d e2 [2] 2b d7 [2] 05 d7 [2] 3a cb }

  condition:
    any of them
}