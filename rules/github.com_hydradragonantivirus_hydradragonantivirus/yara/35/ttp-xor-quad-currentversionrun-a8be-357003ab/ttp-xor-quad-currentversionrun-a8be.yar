rule TTP_XOR_QUAD_CurrentVersionRun_a8be {
  strings:
    $key_a8be = { fb d1 [2] df df [2] f4 f3 [2] da d1 [2] ce ca [2] c1 d0 [2] df cd [2] dd cc [2] c6 ca [2] da cd [2] c6 e2 }

  condition:
    any of them
}