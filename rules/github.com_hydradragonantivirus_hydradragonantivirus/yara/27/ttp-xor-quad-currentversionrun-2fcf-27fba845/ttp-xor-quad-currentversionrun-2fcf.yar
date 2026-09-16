rule TTP_XOR_QUAD_CurrentVersionRun_2fcf {
  strings:
    $key_2fcf = { 7c a0 [2] 58 ae [2] 73 82 [2] 5d a0 [2] 49 bb [2] 46 a1 [2] 58 bc [2] 5a bd [2] 41 bb [2] 5d bc [2] 41 93 }

  condition:
    any of them
}