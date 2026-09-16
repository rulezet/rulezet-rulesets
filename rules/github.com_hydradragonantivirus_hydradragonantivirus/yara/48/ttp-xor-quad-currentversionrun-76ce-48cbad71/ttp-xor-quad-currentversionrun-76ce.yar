rule TTP_XOR_QUAD_CurrentVersionRun_76ce {
  strings:
    $key_76ce = { 25 a1 [2] 01 af [2] 2a 83 [2] 04 a1 [2] 10 ba [2] 1f a0 [2] 01 bd [2] 03 bc [2] 18 ba [2] 04 bd [2] 18 92 }

  condition:
    any of them
}