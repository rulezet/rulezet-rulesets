rule TTP_XOR_QUAD_CurrentVersionRun_cf80 {
  strings:
    $key_cf80 = { 9c ef [2] b8 e1 [2] 93 cd [2] bd ef [2] a9 f4 [2] a6 ee [2] b8 f3 [2] ba f2 [2] a1 f4 [2] bd f3 [2] a1 dc }

  condition:
    any of them
}