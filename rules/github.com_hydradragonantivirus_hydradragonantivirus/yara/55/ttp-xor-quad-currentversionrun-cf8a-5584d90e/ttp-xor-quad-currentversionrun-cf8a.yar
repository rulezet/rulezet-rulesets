rule TTP_XOR_QUAD_CurrentVersionRun_cf8a {
  strings:
    $key_cf8a = { 9c e5 [2] b8 eb [2] 93 c7 [2] bd e5 [2] a9 fe [2] a6 e4 [2] b8 f9 [2] ba f8 [2] a1 fe [2] bd f9 [2] a1 d6 }

  condition:
    any of them
}