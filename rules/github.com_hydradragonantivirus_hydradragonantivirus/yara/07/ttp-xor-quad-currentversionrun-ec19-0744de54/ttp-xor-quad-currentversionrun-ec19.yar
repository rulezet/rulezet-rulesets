rule TTP_XOR_QUAD_CurrentVersionRun_ec19 {
  strings:
    $key_ec19 = { bf 76 [2] 9b 78 [2] b0 54 [2] 9e 76 [2] 8a 6d [2] 85 77 [2] 9b 6a [2] 99 6b [2] 82 6d [2] 9e 6a [2] 82 45 }

  condition:
    any of them
}