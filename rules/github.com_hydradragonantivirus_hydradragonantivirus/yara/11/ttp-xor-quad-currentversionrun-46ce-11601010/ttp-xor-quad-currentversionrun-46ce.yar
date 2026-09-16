rule TTP_XOR_QUAD_CurrentVersionRun_46ce {
  strings:
    $key_46ce = { 15 a1 [2] 31 af [2] 1a 83 [2] 34 a1 [2] 20 ba [2] 2f a0 [2] 31 bd [2] 33 bc [2] 28 ba [2] 34 bd [2] 28 92 }

  condition:
    any of them
}