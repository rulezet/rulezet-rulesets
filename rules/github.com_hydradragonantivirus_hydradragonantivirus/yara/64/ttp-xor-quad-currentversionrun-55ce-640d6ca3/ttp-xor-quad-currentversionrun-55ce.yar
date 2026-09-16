rule TTP_XOR_QUAD_CurrentVersionRun_55ce {
  strings:
    $key_55ce = { 06 a1 [2] 22 af [2] 09 83 [2] 27 a1 [2] 33 ba [2] 3c a0 [2] 22 bd [2] 20 bc [2] 3b ba [2] 27 bd [2] 3b 92 }

  condition:
    any of them
}