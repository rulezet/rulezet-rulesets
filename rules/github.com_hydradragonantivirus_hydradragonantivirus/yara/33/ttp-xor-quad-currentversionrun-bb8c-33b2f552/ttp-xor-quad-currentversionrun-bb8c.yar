rule TTP_XOR_QUAD_CurrentVersionRun_bb8c {
  strings:
    $key_bb8c = { e8 e3 [2] cc ed [2] e7 c1 [2] c9 e3 [2] dd f8 [2] d2 e2 [2] cc ff [2] ce fe [2] d5 f8 [2] c9 ff [2] d5 d0 }

  condition:
    any of them
}