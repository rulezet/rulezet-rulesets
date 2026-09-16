rule TTP_XOR_QUAD_CurrentVersionRun_ec08 {
  strings:
    $key_ec08 = { bf 67 [2] 9b 69 [2] b0 45 [2] 9e 67 [2] 8a 7c [2] 85 66 [2] 9b 7b [2] 99 7a [2] 82 7c [2] 9e 7b [2] 82 54 }

  condition:
    any of them
}