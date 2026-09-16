rule TTP_XOR_QUAD_CurrentVersionRun_8886 {
  strings:
    $key_8886 = { db e9 [2] ff e7 [2] d4 cb [2] fa e9 [2] ee f2 [2] e1 e8 [2] ff f5 [2] fd f4 [2] e6 f2 [2] fa f5 [2] e6 da }

  condition:
    any of them
}