rule TTP_XOR_QUAD_CurrentVersionRun_41fd {
  strings:
    $key_41fd = { 12 92 [2] 36 9c [2] 1d b0 [2] 33 92 [2] 27 89 [2] 28 93 [2] 36 8e [2] 34 8f [2] 2f 89 [2] 33 8e [2] 2f a1 }

  condition:
    any of them
}