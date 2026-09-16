rule TTP_XOR_QUAD_CurrentVersionRun_ec57 {
  strings:
    $key_ec57 = { bf 38 [2] 9b 36 [2] b0 1a [2] 9e 38 [2] 8a 23 [2] 85 39 [2] 9b 24 [2] 99 25 [2] 82 23 [2] 9e 24 [2] 82 0b }

  condition:
    any of them
}