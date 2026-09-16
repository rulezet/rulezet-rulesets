rule TTP_XOR_QUAD_CurrentVersionRun_18cf {
  strings:
    $key_18cf = { 4b a0 [2] 6f ae [2] 44 82 [2] 6a a0 [2] 7e bb [2] 71 a1 [2] 6f bc [2] 6d bd [2] 76 bb [2] 6a bc [2] 76 93 }

  condition:
    any of them
}