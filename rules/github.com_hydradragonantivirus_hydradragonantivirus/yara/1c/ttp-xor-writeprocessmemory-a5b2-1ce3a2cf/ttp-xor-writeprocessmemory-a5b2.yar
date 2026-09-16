rule TTP_XOR_WriteProcessMemory_a5b2 {
  strings:
    $key_a5b2 = { f2 c0 [2] c0 e2 [2] c6 d7 [2] e8 d7 [2] d7 cb }

  condition:
    any of them
}