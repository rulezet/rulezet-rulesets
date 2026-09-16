rule TTP_XOR_QUAD_CurrentVersionRun_28cf {
  strings:
    $key_28cf = { 7b a0 [2] 5f ae [2] 74 82 [2] 5a a0 [2] 4e bb [2] 41 a1 [2] 5f bc [2] 5d bd [2] 46 bb [2] 5a bc [2] 46 93 }

  condition:
    any of them
}