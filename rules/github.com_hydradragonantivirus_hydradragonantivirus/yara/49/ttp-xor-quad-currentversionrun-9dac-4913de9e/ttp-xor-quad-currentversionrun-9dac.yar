rule TTP_XOR_QUAD_CurrentVersionRun_9dac {
  strings:
    $key_9dac = { ce c3 [2] ea cd [2] c1 e1 [2] ef c3 [2] fb d8 [2] f4 c2 [2] ea df [2] e8 de [2] f3 d8 [2] ef df [2] f3 f0 }

  condition:
    any of them
}