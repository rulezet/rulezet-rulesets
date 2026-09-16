rule TTP_XOR_QUAD_CurrentVersionRun_ec45 {
  strings:
    $key_ec45 = { bf 2a [2] 9b 24 [2] b0 08 [2] 9e 2a [2] 8a 31 [2] 85 2b [2] 9b 36 [2] 99 37 [2] 82 31 [2] 9e 36 [2] 82 19 }

  condition:
    any of them
}