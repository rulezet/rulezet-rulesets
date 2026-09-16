rule TTP_XOR_QUAD_CurrentVersionRun_17d3 {
  strings:
    $key_17d3 = { 44 bc [2] 60 b2 [2] 4b 9e [2] 65 bc [2] 71 a7 [2] 7e bd [2] 60 a0 [2] 62 a1 [2] 79 a7 [2] 65 a0 [2] 79 8f }

  condition:
    any of them
}