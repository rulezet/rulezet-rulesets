rule TTP_XOR_QUAD_CurrentVersionRun_5ecf {
  strings:
    $key_5ecf = { 0d a0 [2] 29 ae [2] 02 82 [2] 2c a0 [2] 38 bb [2] 37 a1 [2] 29 bc [2] 2b bd [2] 30 bb [2] 2c bc [2] 30 93 }

  condition:
    any of them
}