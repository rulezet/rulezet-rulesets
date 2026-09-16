rule TTP_XOR_QUAD_CurrentVersionRun_33cf {
  strings:
    $key_33cf = { 60 a0 [2] 44 ae [2] 6f 82 [2] 41 a0 [2] 55 bb [2] 5a a1 [2] 44 bc [2] 46 bd [2] 5d bb [2] 41 bc [2] 5d 93 }

  condition:
    any of them
}