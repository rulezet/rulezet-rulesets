rule TTP_XOR_QUAD_CurrentVersionRun_ec44 {
  strings:
    $key_ec44 = { bf 2b [2] 9b 25 [2] b0 09 [2] 9e 2b [2] 8a 30 [2] 85 2a [2] 9b 37 [2] 99 36 [2] 82 30 [2] 9e 37 [2] 82 18 }

  condition:
    any of them
}