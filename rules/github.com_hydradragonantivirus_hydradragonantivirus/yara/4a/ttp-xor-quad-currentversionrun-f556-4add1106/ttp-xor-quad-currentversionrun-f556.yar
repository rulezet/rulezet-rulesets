rule TTP_XOR_QUAD_CurrentVersionRun_f556 {
  strings:
    $key_f556 = { a6 39 [2] 82 37 [2] a9 1b [2] 87 39 [2] 93 22 [2] 9c 38 [2] 82 25 [2] 80 24 [2] 9b 22 [2] 87 25 [2] 9b 0a }

  condition:
    any of them
}