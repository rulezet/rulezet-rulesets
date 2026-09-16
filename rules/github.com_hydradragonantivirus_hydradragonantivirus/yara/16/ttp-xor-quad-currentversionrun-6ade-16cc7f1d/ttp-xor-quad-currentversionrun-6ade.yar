rule TTP_XOR_QUAD_CurrentVersionRun_6ade {
  strings:
    $key_6ade = { 39 b1 [2] 1d bf [2] 36 93 [2] 18 b1 [2] 0c aa [2] 03 b0 [2] 1d ad [2] 1f ac [2] 04 aa [2] 18 ad [2] 04 82 }

  condition:
    any of them
}