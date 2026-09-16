rule TTP_XOR_QUAD_CurrentVersionRun_af8b {
  strings:
    $key_af8b = { fc e4 [2] d8 ea [2] f3 c6 [2] dd e4 [2] c9 ff [2] c6 e5 [2] d8 f8 [2] da f9 [2] c1 ff [2] dd f8 [2] c1 d7 }

  condition:
    any of them
}