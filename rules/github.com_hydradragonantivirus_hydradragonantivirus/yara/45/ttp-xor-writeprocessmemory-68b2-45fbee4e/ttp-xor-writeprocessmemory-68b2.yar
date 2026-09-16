rule TTP_XOR_WriteProcessMemory_68b2 {
  strings:
    $key_68b2 = { 3f c0 [2] 0d e2 [2] 0b d7 [2] 25 d7 [2] 1a cb }

  condition:
    any of them
}