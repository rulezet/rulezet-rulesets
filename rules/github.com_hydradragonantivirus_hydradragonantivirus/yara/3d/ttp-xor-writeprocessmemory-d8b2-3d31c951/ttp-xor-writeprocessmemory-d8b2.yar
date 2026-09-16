rule TTP_XOR_WriteProcessMemory_d8b2 {
  strings:
    $key_d8b2 = { 8f c0 [2] bd e2 [2] bb d7 [2] 95 d7 [2] aa cb }

  condition:
    any of them
}