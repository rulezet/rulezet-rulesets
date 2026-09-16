rule TTP_XOR_QUAD_CurrentVersionRun_ec0e {
  strings:
    $key_ec0e = { bf 61 [2] 9b 6f [2] b0 43 [2] 9e 61 [2] 8a 7a [2] 85 60 [2] 9b 7d [2] 99 7c [2] 82 7a [2] 9e 7d [2] 82 52 }

  condition:
    any of them
}