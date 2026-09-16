rule TTP_XOR_QUAD_CurrentVersionRun_48ce {
  strings:
    $key_48ce = { 1b a1 [2] 3f af [2] 14 83 [2] 3a a1 [2] 2e ba [2] 21 a0 [2] 3f bd [2] 3d bc [2] 26 ba [2] 3a bd [2] 26 92 }

  condition:
    any of them
}