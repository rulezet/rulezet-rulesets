rule TTP_XOR_QUAD_CurrentVersionRun_42ce {
  strings:
    $key_42ce = { 11 a1 [2] 35 af [2] 1e 83 [2] 30 a1 [2] 24 ba [2] 2b a0 [2] 35 bd [2] 37 bc [2] 2c ba [2] 30 bd [2] 2c 92 }

  condition:
    any of them
}