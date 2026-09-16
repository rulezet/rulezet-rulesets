rule TTP_XOR_QUAD_CurrentVersionRun_cfa8 {
  strings:
    $key_cfa8 = { 9c c7 [2] b8 c9 [2] 93 e5 [2] bd c7 [2] a9 dc [2] a6 c6 [2] b8 db [2] ba da [2] a1 dc [2] bd db [2] a1 f4 }

  condition:
    any of them
}