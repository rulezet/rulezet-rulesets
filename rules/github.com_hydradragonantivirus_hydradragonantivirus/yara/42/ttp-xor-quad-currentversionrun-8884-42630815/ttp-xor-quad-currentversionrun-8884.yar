rule TTP_XOR_QUAD_CurrentVersionRun_8884 {
  strings:
    $key_8884 = { db eb [2] ff e5 [2] d4 c9 [2] fa eb [2] ee f0 [2] e1 ea [2] ff f7 [2] fd f6 [2] e6 f0 [2] fa f7 [2] e6 d8 }

  condition:
    any of them
}