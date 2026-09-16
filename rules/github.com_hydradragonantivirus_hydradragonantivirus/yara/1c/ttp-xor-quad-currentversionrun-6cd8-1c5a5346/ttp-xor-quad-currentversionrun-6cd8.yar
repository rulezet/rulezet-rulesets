rule TTP_XOR_QUAD_CurrentVersionRun_6cd8 {
  strings:
    $key_6cd8 = { 3f b7 [2] 1b b9 [2] 30 95 [2] 1e b7 [2] 0a ac [2] 05 b6 [2] 1b ab [2] 19 aa [2] 02 ac [2] 1e ab [2] 02 84 }

  condition:
    any of them
}