rule TTP_XOR_QUAD_CurrentVersionRun_86ac {
  strings:
    $key_86ac = { d5 c3 [2] f1 cd [2] da e1 [2] f4 c3 [2] e0 d8 [2] ef c2 [2] f1 df [2] f3 de [2] e8 d8 [2] f4 df [2] e8 f0 }

  condition:
    any of them
}