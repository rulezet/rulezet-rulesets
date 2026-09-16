rule TTP_XOR_QUAD_CurrentVersionRun_ec5a {
  strings:
    $key_ec5a = { bf 35 [2] 9b 3b [2] b0 17 [2] 9e 35 [2] 8a 2e [2] 85 34 [2] 9b 29 [2] 99 28 [2] 82 2e [2] 9e 29 [2] 82 06 }

  condition:
    any of them
}