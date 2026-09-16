rule TTP_XOR_WriteProcessMemory_f0b2 {
  strings:
    $key_f0b2 = { a7 c0 [2] 95 e2 [2] 93 d7 [2] bd d7 [2] 82 cb }

  condition:
    any of them
}