rule TTP_XOR_QUAD_CurrentVersionRun_5ade {
  strings:
    $key_5ade = { 09 b1 [2] 2d bf [2] 06 93 [2] 28 b1 [2] 3c aa [2] 33 b0 [2] 2d ad [2] 2f ac [2] 34 aa [2] 28 ad [2] 34 82 }

  condition:
    any of them
}