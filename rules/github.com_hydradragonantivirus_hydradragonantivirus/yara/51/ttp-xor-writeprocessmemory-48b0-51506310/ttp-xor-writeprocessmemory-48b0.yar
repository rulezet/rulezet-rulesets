rule TTP_XOR_WriteProcessMemory_48b0 {
  strings:
    $key_48b0 = { 1f c2 [2] 2d e0 [2] 2b d5 [2] 05 d5 [2] 3a c9 }

  condition:
    any of them
}