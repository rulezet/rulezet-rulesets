rule TTP_XOR_QUAD_CurrentVersionRun_0acf {
  strings:
    $key_0acf = { 59 a0 [2] 7d ae [2] 56 82 [2] 78 a0 [2] 6c bb [2] 63 a1 [2] 7d bc [2] 7f bd [2] 64 bb [2] 78 bc [2] 64 93 }

  condition:
    any of them
}