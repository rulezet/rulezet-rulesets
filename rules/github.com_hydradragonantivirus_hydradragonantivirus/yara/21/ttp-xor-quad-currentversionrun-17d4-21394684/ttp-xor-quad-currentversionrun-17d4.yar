rule TTP_XOR_QUAD_CurrentVersionRun_17d4 {
  strings:
    $key_17d4 = { 44 bb [2] 60 b5 [2] 4b 99 [2] 65 bb [2] 71 a0 [2] 7e ba [2] 60 a7 [2] 62 a6 [2] 79 a0 [2] 65 a7 [2] 79 88 }

  condition:
    any of them
}