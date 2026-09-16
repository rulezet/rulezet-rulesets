rule TTP_XOR_QUAD_CurrentVersionRun_ec07 {
  strings:
    $key_ec07 = { bf 68 [2] 9b 66 [2] b0 4a [2] 9e 68 [2] 8a 73 [2] 85 69 [2] 9b 74 [2] 99 75 [2] 82 73 [2] 9e 74 [2] 82 5b }

  condition:
    any of them
}