rule TTP_XOR_QUAD_CurrentVersionRun_8d97 {
  strings:
    $key_8d97 = { de f8 [2] fa f6 [2] d1 da [2] ff f8 [2] eb e3 [2] e4 f9 [2] fa e4 [2] f8 e5 [2] e3 e3 [2] ff e4 [2] e3 cb }

  condition:
    any of them
}