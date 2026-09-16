rule TTP_XOR_QUAD_CurrentVersionRun_8d86 {
  strings:
    $key_8d86 = { de e9 [2] fa e7 [2] d1 cb [2] ff e9 [2] eb f2 [2] e4 e8 [2] fa f5 [2] f8 f4 [2] e3 f2 [2] ff f5 [2] e3 da }

  condition:
    any of them
}