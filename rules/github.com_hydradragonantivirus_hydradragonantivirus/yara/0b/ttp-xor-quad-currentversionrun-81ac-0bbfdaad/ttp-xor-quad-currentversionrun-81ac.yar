rule TTP_XOR_QUAD_CurrentVersionRun_81ac {
  strings:
    $key_81ac = { d2 c3 [2] f6 cd [2] dd e1 [2] f3 c3 [2] e7 d8 [2] e8 c2 [2] f6 df [2] f4 de [2] ef d8 [2] f3 df [2] ef f0 }

  condition:
    any of them
}