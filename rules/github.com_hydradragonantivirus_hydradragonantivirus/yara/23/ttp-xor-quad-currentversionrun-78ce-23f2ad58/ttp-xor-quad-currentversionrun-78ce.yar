rule TTP_XOR_QUAD_CurrentVersionRun_78ce {
  strings:
    $key_78ce = { 2b a1 [2] 0f af [2] 24 83 [2] 0a a1 [2] 1e ba [2] 11 a0 [2] 0f bd [2] 0d bc [2] 16 ba [2] 0a bd [2] 16 92 }

  condition:
    any of them
}