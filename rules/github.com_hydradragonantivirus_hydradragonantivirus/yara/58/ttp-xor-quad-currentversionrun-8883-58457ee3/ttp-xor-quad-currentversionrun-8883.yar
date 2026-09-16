rule TTP_XOR_QUAD_CurrentVersionRun_8883 {
  strings:
    $key_8883 = { db ec [2] ff e2 [2] d4 ce [2] fa ec [2] ee f7 [2] e1 ed [2] ff f0 [2] fd f1 [2] e6 f7 [2] fa f0 [2] e6 df }

  condition:
    any of them
}