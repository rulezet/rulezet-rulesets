rule TTP_XOR_QUAD_CurrentVersionRun_3156 {
  strings:
    $key_3156 = { 62 39 [2] 46 37 [2] 6d 1b [2] 43 39 [2] 57 22 [2] 58 38 [2] 46 25 [2] 44 24 [2] 5f 22 [2] 43 25 [2] 5f 0a }

  condition:
    any of them
}