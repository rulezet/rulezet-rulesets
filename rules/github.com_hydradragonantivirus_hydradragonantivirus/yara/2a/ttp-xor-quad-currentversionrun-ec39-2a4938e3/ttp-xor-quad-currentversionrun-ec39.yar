rule TTP_XOR_QUAD_CurrentVersionRun_ec39 {
  strings:
    $key_ec39 = { bf 56 [2] 9b 58 [2] b0 74 [2] 9e 56 [2] 8a 4d [2] 85 57 [2] 9b 4a [2] 99 4b [2] 82 4d [2] 9e 4a [2] 82 65 }

  condition:
    any of them
}