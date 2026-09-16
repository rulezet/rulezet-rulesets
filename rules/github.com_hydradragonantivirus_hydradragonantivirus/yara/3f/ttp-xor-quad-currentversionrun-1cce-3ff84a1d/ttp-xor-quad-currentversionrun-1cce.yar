rule TTP_XOR_QUAD_CurrentVersionRun_1cce {
  strings:
    $key_1cce = { 4f a1 [2] 6b af [2] 40 83 [2] 6e a1 [2] 7a ba [2] 75 a0 [2] 6b bd [2] 69 bc [2] 72 ba [2] 6e bd [2] 72 92 }

  condition:
    any of them
}