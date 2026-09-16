rule TTP_XOR_QUAD_CurrentVersionRun_0cce {
  strings:
    $key_0cce = { 5f a1 [2] 7b af [2] 50 83 [2] 7e a1 [2] 6a ba [2] 65 a0 [2] 7b bd [2] 79 bc [2] 62 ba [2] 7e bd [2] 62 92 }

  condition:
    any of them
}