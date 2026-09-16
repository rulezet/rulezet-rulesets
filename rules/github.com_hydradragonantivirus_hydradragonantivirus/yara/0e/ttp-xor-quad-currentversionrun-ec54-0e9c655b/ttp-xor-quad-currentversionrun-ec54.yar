rule TTP_XOR_QUAD_CurrentVersionRun_ec54 {
  strings:
    $key_ec54 = { bf 3b [2] 9b 35 [2] b0 19 [2] 9e 3b [2] 8a 20 [2] 85 3a [2] 9b 27 [2] 99 26 [2] 82 20 [2] 9e 27 [2] 82 08 }

  condition:
    any of them
}