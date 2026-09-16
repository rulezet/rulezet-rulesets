rule TTP_XOR_QUAD_CurrentVersionRun_ca9d {
  strings:
    $key_ca9d = { 99 f2 [2] bd fc [2] 96 d0 [2] b8 f2 [2] ac e9 [2] a3 f3 [2] bd ee [2] bf ef [2] a4 e9 [2] b8 ee [2] a4 c1 }

  condition:
    any of them
}