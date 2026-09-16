rule TTP_XOR_QUAD_CurrentVersionRun_17d9 {
  strings:
    $key_17d9 = { 44 b6 [2] 60 b8 [2] 4b 94 [2] 65 b6 [2] 71 ad [2] 7e b7 [2] 60 aa [2] 62 ab [2] 79 ad [2] 65 aa [2] 79 85 }

  condition:
    any of them
}