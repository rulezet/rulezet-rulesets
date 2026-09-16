rule TTP_XOR_QUAD_CurrentVersionRun_d4a8 {
  strings:
    $key_d4a8 = { 87 c7 [2] a3 c9 [2] 88 e5 [2] a6 c7 [2] b2 dc [2] bd c6 [2] a3 db [2] a1 da [2] ba dc [2] a6 db [2] ba f4 }

  condition:
    any of them
}