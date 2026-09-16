rule TTP_XOR_QUAD_CurrentVersionRun_e8ce {
  strings:
    $key_e8ce = { bb a1 [2] 9f af [2] b4 83 [2] 9a a1 [2] 8e ba [2] 81 a0 [2] 9f bd [2] 9d bc [2] 86 ba [2] 9a bd [2] 86 92 }

  condition:
    any of them
}