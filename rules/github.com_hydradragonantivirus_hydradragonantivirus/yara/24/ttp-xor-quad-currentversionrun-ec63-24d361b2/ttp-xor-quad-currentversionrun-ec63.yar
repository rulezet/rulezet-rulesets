rule TTP_XOR_QUAD_CurrentVersionRun_ec63 {
  strings:
    $key_ec63 = { bf 0c [2] 9b 02 [2] b0 2e [2] 9e 0c [2] 8a 17 [2] 85 0d [2] 9b 10 [2] 99 11 [2] 82 17 [2] 9e 10 [2] 82 3f }

  condition:
    any of them
}