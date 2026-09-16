rule TTP_XOR_QUAD_CurrentVersionRun_d496 {
  strings:
    $key_d496 = { 87 f9 [2] a3 f7 [2] 88 db [2] a6 f9 [2] b2 e2 [2] bd f8 [2] a3 e5 [2] a1 e4 [2] ba e2 [2] a6 e5 [2] ba ca }

  condition:
    any of them
}