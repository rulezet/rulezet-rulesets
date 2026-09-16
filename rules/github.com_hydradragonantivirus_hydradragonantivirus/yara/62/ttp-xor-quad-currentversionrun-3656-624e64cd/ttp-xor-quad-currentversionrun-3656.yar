rule TTP_XOR_QUAD_CurrentVersionRun_3656 {
  strings:
    $key_3656 = { 65 39 [2] 41 37 [2] 6a 1b [2] 44 39 [2] 50 22 [2] 5f 38 [2] 41 25 [2] 43 24 [2] 58 22 [2] 44 25 [2] 58 0a }

  condition:
    any of them
}