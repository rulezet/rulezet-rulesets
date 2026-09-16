rule TTP_XOR_WriteProcessMemory_95b2 {
  strings:
    $key_95b2 = { c2 c0 [2] f0 e2 [2] f6 d7 [2] d8 d7 [2] e7 cb }

  condition:
    any of them
}