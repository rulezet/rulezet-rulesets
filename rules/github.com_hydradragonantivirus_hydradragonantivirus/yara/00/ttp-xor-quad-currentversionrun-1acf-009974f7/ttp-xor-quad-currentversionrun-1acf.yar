rule TTP_XOR_QUAD_CurrentVersionRun_1acf {
  strings:
    $key_1acf = { 49 a0 [2] 6d ae [2] 46 82 [2] 68 a0 [2] 7c bb [2] 73 a1 [2] 6d bc [2] 6f bd [2] 74 bb [2] 68 bc [2] 74 93 }

  condition:
    any of them
}