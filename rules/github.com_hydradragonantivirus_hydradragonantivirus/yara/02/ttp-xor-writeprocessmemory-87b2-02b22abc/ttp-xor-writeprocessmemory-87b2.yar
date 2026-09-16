rule TTP_XOR_WriteProcessMemory_87b2 {
  strings:
    $key_87b2 = { d0 c0 [2] e2 e2 [2] e4 d7 [2] ca d7 [2] f5 cb }

  condition:
    any of them
}