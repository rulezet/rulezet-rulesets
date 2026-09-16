rule TTP_XOR_QUAD_CurrentVersionRun_2acf {
  strings:
    $key_2acf = { 79 a0 [2] 5d ae [2] 76 82 [2] 58 a0 [2] 4c bb [2] 43 a1 [2] 5d bc [2] 5f bd [2] 44 bb [2] 58 bc [2] 44 93 }

  condition:
    any of them
}