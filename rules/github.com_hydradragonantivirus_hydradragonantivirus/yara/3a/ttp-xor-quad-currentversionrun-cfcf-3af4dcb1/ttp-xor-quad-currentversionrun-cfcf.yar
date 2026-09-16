rule TTP_XOR_QUAD_CurrentVersionRun_cfcf {
  strings:
    $key_cfcf = { 9c a0 [2] b8 ae [2] 93 82 [2] bd a0 [2] a9 bb [2] a6 a1 [2] b8 bc [2] ba bd [2] a1 bb [2] bd bc [2] a1 93 }

  condition:
    any of them
}