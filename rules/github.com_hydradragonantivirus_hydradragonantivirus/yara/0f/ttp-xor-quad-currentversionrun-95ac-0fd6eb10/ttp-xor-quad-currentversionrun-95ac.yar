rule TTP_XOR_QUAD_CurrentVersionRun_95ac {
  strings:
    $key_95ac = { c6 c3 [2] e2 cd [2] c9 e1 [2] e7 c3 [2] f3 d8 [2] fc c2 [2] e2 df [2] e0 de [2] fb d8 [2] e7 df [2] fb f0 }

  condition:
    any of them
}