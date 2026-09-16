rule TTP_XOR_QUAD_CurrentVersionRun_ecce {
  strings:
    $key_ecce = { bf a1 [2] 9b af [2] b0 83 [2] 9e a1 [2] 8a ba [2] 85 a0 [2] 9b bd [2] 99 bc [2] 82 ba [2] 9e bd [2] 82 92 }

  condition:
    any of them
}