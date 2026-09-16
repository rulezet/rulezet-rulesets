rule TTP_XOR_QUAD_CurrentVersionRun_4fcf {
  strings:
    $key_4fcf = { 1c a0 [2] 38 ae [2] 13 82 [2] 3d a0 [2] 29 bb [2] 26 a1 [2] 38 bc [2] 3a bd [2] 21 bb [2] 3d bc [2] 21 93 }

  condition:
    any of them
}