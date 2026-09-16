rule TTP_XOR_QUAD_CurrentVersionRun_4cce {
  strings:
    $key_4cce = { 1f a1 [2] 3b af [2] 10 83 [2] 3e a1 [2] 2a ba [2] 25 a0 [2] 3b bd [2] 39 bc [2] 22 ba [2] 3e bd [2] 22 92 }

  condition:
    any of them
}