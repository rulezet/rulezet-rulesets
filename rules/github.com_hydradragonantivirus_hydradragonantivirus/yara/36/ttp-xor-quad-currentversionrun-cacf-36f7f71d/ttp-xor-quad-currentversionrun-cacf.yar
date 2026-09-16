rule TTP_XOR_QUAD_CurrentVersionRun_cacf {
  strings:
    $key_cacf = { 99 a0 [2] bd ae [2] 96 82 [2] b8 a0 [2] ac bb [2] a3 a1 [2] bd bc [2] bf bd [2] a4 bb [2] b8 bc [2] a4 93 }

  condition:
    any of them
}