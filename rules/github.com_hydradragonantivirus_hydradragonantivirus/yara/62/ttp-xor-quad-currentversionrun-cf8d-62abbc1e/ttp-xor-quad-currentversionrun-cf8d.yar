rule TTP_XOR_QUAD_CurrentVersionRun_cf8d {
  strings:
    $key_cf8d = { 9c e2 [2] b8 ec [2] 93 c0 [2] bd e2 [2] a9 f9 [2] a6 e3 [2] b8 fe [2] ba ff [2] a1 f9 [2] bd fe [2] a1 d1 }

  condition:
    any of them
}