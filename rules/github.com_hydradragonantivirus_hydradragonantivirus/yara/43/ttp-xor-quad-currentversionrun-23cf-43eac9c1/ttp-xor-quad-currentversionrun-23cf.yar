rule TTP_XOR_QUAD_CurrentVersionRun_23cf {
  strings:
    $key_23cf = { 70 a0 [2] 54 ae [2] 7f 82 [2] 51 a0 [2] 45 bb [2] 4a a1 [2] 54 bc [2] 56 bd [2] 4d bb [2] 51 bc [2] 4d 93 }

  condition:
    any of them
}