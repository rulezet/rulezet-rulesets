rule TTP_XOR_QUAD_CurrentVersionRun_ec1e {
  strings:
    $key_ec1e = { bf 71 [2] 9b 7f [2] b0 53 [2] 9e 71 [2] 8a 6a [2] 85 70 [2] 9b 6d [2] 99 6c [2] 82 6a [2] 9e 6d [2] 82 42 }

  condition:
    any of them
}