rule TTP_XOR_QUAD_CurrentVersionRun_6acf {
  strings:
    $key_6acf = { 39 a0 [2] 1d ae [2] 36 82 [2] 18 a0 [2] 0c bb [2] 03 a1 [2] 1d bc [2] 1f bd [2] 04 bb [2] 18 bc [2] 04 93 }

  condition:
    any of them
}