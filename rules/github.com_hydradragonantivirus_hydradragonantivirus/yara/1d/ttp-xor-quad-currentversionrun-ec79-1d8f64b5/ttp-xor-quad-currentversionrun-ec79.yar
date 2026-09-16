rule TTP_XOR_QUAD_CurrentVersionRun_ec79 {
  strings:
    $key_ec79 = { bf 16 [2] 9b 18 [2] b0 34 [2] 9e 16 [2] 8a 0d [2] 85 17 [2] 9b 0a [2] 99 0b [2] 82 0d [2] 9e 0a [2] 82 25 }

  condition:
    any of them
}