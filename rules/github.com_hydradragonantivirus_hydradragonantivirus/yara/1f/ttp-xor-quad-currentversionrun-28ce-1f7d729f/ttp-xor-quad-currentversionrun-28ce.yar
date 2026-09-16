rule TTP_XOR_QUAD_CurrentVersionRun_28ce {
  strings:
    $key_28ce = { 7b a1 [2] 5f af [2] 74 83 [2] 5a a1 [2] 4e ba [2] 41 a0 [2] 5f bd [2] 5d bc [2] 46 ba [2] 5a bd [2] 46 92 }

  condition:
    any of them
}