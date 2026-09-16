rule TTP_XOR_QUAD_CurrentVersionRun_ec24 {
  strings:
    $key_ec24 = { bf 4b [2] 9b 45 [2] b0 69 [2] 9e 4b [2] 8a 50 [2] 85 4a [2] 9b 57 [2] 99 56 [2] 82 50 [2] 9e 57 [2] 82 78 }

  condition:
    any of them
}