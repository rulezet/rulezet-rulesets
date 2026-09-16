rule TTP_XOR_QUAD_CurrentVersionRun_8887 {
  strings:
    $key_8887 = { db e8 [2] ff e6 [2] d4 ca [2] fa e8 [2] ee f3 [2] e1 e9 [2] ff f4 [2] fd f5 [2] e6 f3 [2] fa f4 [2] e6 db }

  condition:
    any of them
}