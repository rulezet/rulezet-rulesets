rule TTP_XOR_QUAD_CurrentVersionRun_d484 {
  strings:
    $key_d484 = { 87 eb [2] a3 e5 [2] 88 c9 [2] a6 eb [2] b2 f0 [2] bd ea [2] a3 f7 [2] a1 f6 [2] ba f0 [2] a6 f7 [2] ba d8 }

  condition:
    any of them
}