rule TTP_XOR_QUAD_CurrentVersionRun_9db0 {
  strings:
    $key_9db0 = { ce df [2] ea d1 [2] c1 fd [2] ef df [2] fb c4 [2] f4 de [2] ea c3 [2] e8 c2 [2] f3 c4 [2] ef c3 [2] f3 ec }

  condition:
    any of them
}