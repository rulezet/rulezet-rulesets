rule TTP_XOR_QUAD_CurrentVersionRun_4ecf {
  strings:
    $key_4ecf = { 1d a0 [2] 39 ae [2] 12 82 [2] 3c a0 [2] 28 bb [2] 27 a1 [2] 39 bc [2] 3b bd [2] 20 bb [2] 3c bc [2] 20 93 }

  condition:
    any of them
}