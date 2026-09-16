rule TTP_XOR_QUAD_CurrentVersionRun_58cf {
  strings:
    $key_58cf = { 0b a0 [2] 2f ae [2] 04 82 [2] 2a a0 [2] 3e bb [2] 31 a1 [2] 2f bc [2] 2d bd [2] 36 bb [2] 2a bc [2] 36 93 }

  condition:
    any of them
}