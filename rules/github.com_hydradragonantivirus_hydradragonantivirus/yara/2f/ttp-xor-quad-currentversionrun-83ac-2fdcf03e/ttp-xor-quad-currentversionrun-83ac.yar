rule TTP_XOR_QUAD_CurrentVersionRun_83ac {
  strings:
    $key_83ac = { d0 c3 [2] f4 cd [2] df e1 [2] f1 c3 [2] e5 d8 [2] ea c2 [2] f4 df [2] f6 de [2] ed d8 [2] f1 df [2] ed f0 }

  condition:
    any of them
}