rule TTP_XOR_QUAD_CurrentVersionRun_c88d {
  strings:
    $key_c88d = { 9b e2 [2] bf ec [2] 94 c0 [2] ba e2 [2] ae f9 [2] a1 e3 [2] bf fe [2] bd ff [2] a6 f9 [2] ba fe [2] a6 d1 }

  condition:
    any of them
}