rule TTP_XOR_QUAD_CurrentVersionRun_ec56 {
  strings:
    $key_ec56 = { bf 39 [2] 9b 37 [2] b0 1b [2] 9e 39 [2] 8a 22 [2] 85 38 [2] 9b 25 [2] 99 24 [2] 82 22 [2] 9e 25 [2] 82 0a }

  condition:
    any of them
}