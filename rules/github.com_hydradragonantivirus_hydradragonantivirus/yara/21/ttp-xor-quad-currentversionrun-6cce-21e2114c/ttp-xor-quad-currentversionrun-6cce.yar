rule TTP_XOR_QUAD_CurrentVersionRun_6cce {
  strings:
    $key_6cce = { 3f a1 [2] 1b af [2] 30 83 [2] 1e a1 [2] 0a ba [2] 05 a0 [2] 1b bd [2] 19 bc [2] 02 ba [2] 1e bd [2] 02 92 }

  condition:
    any of them
}