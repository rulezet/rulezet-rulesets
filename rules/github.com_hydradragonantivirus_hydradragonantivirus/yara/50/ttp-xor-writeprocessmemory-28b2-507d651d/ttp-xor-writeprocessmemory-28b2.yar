rule TTP_XOR_WriteProcessMemory_28b2 {
  strings:
    $key_28b2 = { 7f c0 [2] 4d e2 [2] 4b d7 [2] 65 d7 [2] 5a cb }

  condition:
    any of them
}