rule TTP_XOR_QUAD_CurrentVersionRun_84ac {
  strings:
    $key_84ac = { d7 c3 [2] f3 cd [2] d8 e1 [2] f6 c3 [2] e2 d8 [2] ed c2 [2] f3 df [2] f1 de [2] ea d8 [2] f6 df [2] ea f0 }

  condition:
    any of them
}