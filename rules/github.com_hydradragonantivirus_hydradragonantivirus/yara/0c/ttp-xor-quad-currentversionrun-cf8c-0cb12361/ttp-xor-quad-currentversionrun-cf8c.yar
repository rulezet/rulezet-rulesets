rule TTP_XOR_QUAD_CurrentVersionRun_cf8c {
  strings:
    $key_cf8c = { 9c e3 [2] b8 ed [2] 93 c1 [2] bd e3 [2] a9 f8 [2] a6 e2 [2] b8 ff [2] ba fe [2] a1 f8 [2] bd ff [2] a1 d0 }

  condition:
    any of them
}