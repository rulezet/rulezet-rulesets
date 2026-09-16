rule TTP_XOR_QUAD_CurrentVersionRun_08ce {
  strings:
    $key_08ce = { 5b a1 [2] 7f af [2] 54 83 [2] 7a a1 [2] 6e ba [2] 61 a0 [2] 7f bd [2] 7d bc [2] 66 ba [2] 7a bd [2] 66 92 }

  condition:
    any of them
}