rule TTP_XOR_QUAD_CurrentVersionRun_44ce {
  strings:
    $key_44ce = { 17 a1 [2] 33 af [2] 18 83 [2] 36 a1 [2] 22 ba [2] 2d a0 [2] 33 bd [2] 31 bc [2] 2a ba [2] 36 bd [2] 2a 92 }

  condition:
    any of them
}