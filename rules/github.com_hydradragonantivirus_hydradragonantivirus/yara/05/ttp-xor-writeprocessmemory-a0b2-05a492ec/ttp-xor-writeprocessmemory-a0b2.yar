rule TTP_XOR_WriteProcessMemory_a0b2 {
  strings:
    $key_a0b2 = { f7 c0 [2] c5 e2 [2] c3 d7 [2] ed d7 [2] d2 cb }

  condition:
    any of them
}