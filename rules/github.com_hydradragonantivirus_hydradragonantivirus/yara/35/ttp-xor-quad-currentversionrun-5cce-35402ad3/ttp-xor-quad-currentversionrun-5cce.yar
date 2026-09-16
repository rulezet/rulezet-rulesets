rule TTP_XOR_QUAD_CurrentVersionRun_5cce {
  strings:
    $key_5cce = { 0f a1 [2] 2b af [2] 00 83 [2] 2e a1 [2] 3a ba [2] 35 a0 [2] 2b bd [2] 29 bc [2] 32 ba [2] 2e bd [2] 32 92 }

  condition:
    any of them
}