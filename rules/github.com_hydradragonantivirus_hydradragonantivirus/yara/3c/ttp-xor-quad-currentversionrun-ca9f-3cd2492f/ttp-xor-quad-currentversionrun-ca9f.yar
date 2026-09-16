rule TTP_XOR_QUAD_CurrentVersionRun_ca9f {
  strings:
    $key_ca9f = { 99 f0 [2] bd fe [2] 96 d2 [2] b8 f0 [2] ac eb [2] a3 f1 [2] bd ec [2] bf ed [2] a4 eb [2] b8 ec [2] a4 c3 }

  condition:
    any of them
}