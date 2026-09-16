rule TTP_XOR_WriteProcessMemory_81b2 {
  strings:
    $key_81b2 = { d6 c0 [2] e4 e2 [2] e2 d7 [2] cc d7 [2] f3 cb }

  condition:
    any of them
}