rule TTP_XOR_QUAD_CurrentVersionRun_15cf {
  strings:
    $key_15cf = { 46 a0 [2] 62 ae [2] 49 82 [2] 67 a0 [2] 73 bb [2] 7c a1 [2] 62 bc [2] 60 bd [2] 7b bb [2] 67 bc [2] 7b 93 }

  condition:
    any of them
}