rule TTP_XOR_QUAD_CurrentVersionRun_d4ad {
  strings:
    $key_d4ad = { 87 c2 [2] a3 cc [2] 88 e0 [2] a6 c2 [2] b2 d9 [2] bd c3 [2] a3 de [2] a1 df [2] ba d9 [2] a6 de [2] ba f1 }

  condition:
    any of them
}