rule TTP_XOR_QUAD_CurrentVersionRun_cfc8 {
  strings:
    $key_cfc8 = { 9c a7 [2] b8 a9 [2] 93 85 [2] bd a7 [2] a9 bc [2] a6 a6 [2] b8 bb [2] ba ba [2] a1 bc [2] bd bb [2] a1 94 }

  condition:
    any of them
}