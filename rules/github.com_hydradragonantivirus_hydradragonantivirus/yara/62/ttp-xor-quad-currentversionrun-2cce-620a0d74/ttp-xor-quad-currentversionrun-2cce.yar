rule TTP_XOR_QUAD_CurrentVersionRun_2cce {
  strings:
    $key_2cce = { 7f a1 [2] 5b af [2] 70 83 [2] 5e a1 [2] 4a ba [2] 45 a0 [2] 5b bd [2] 59 bc [2] 42 ba [2] 5e bd [2] 42 92 }

  condition:
    any of them
}