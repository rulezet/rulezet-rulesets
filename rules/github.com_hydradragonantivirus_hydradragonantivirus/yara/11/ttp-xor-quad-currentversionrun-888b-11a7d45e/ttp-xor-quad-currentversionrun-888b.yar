rule TTP_XOR_QUAD_CurrentVersionRun_888b {
  strings:
    $key_888b = { db e4 [2] ff ea [2] d4 c6 [2] fa e4 [2] ee ff [2] e1 e5 [2] ff f8 [2] fd f9 [2] e6 ff [2] fa f8 [2] e6 d7 }

  condition:
    any of them
}