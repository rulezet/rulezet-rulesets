rule TTP_XOR_QUAD_CurrentVersionRun_86b0 {
  strings:
    $key_86b0 = { d5 df [2] f1 d1 [2] da fd [2] f4 df [2] e0 c4 [2] ef de [2] f1 c3 [2] f3 c2 [2] e8 c4 [2] f4 c3 [2] e8 ec }

  condition:
    any of them
}