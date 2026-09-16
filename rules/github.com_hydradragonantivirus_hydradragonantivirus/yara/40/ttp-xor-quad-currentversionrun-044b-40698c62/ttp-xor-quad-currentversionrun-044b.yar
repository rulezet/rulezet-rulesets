rule TTP_XOR_QUAD_CurrentVersionRun_044b {
  strings:
    $key_044b = { 57 24 [2] 73 2a [2] 58 06 [2] 76 24 [2] 62 3f [2] 6d 25 [2] 73 38 [2] 71 39 [2] 6a 3f [2] 76 38 [2] 6a 17 }

  condition:
    any of them
}