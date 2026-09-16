rule TTP_XOR_WriteProcessMemory_b3b2 {
  strings:
    $key_b3b2 = { e4 c0 [2] d6 e2 [2] d0 d7 [2] fe d7 [2] c1 cb }

  condition:
    any of them
}