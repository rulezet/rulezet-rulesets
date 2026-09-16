rule TTP_XOR_QUAD_CurrentVersionRun_cfad {
  strings:
    $key_cfad = { 9c c2 [2] b8 cc [2] 93 e0 [2] bd c2 [2] a9 d9 [2] a6 c3 [2] b8 de [2] ba df [2] a1 d9 [2] bd de [2] a1 f1 }

  condition:
    any of them
}