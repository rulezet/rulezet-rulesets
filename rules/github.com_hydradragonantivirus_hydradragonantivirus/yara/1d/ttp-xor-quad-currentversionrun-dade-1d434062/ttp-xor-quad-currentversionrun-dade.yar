rule TTP_XOR_QUAD_CurrentVersionRun_dade {
  strings:
    $key_dade = { 89 b1 [2] ad bf [2] 86 93 [2] a8 b1 [2] bc aa [2] b3 b0 [2] ad ad [2] af ac [2] b4 aa [2] a8 ad [2] b4 82 }

  condition:
    any of them
}