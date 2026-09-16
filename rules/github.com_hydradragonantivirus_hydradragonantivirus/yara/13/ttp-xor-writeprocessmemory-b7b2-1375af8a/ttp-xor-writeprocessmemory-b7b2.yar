rule TTP_XOR_WriteProcessMemory_b7b2 {
  strings:
    $key_b7b2 = { e0 c0 [2] d2 e2 [2] d4 d7 [2] fa d7 [2] c5 cb }

  condition:
    any of them
}