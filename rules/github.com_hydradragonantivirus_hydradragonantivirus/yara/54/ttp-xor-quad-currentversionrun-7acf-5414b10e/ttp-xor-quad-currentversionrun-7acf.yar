rule TTP_XOR_QUAD_CurrentVersionRun_7acf {
  strings:
    $key_7acf = { 29 a0 [2] 0d ae [2] 26 82 [2] 08 a0 [2] 1c bb [2] 13 a1 [2] 0d bc [2] 0f bd [2] 14 bb [2] 08 bc [2] 14 93 }

  condition:
    any of them
}