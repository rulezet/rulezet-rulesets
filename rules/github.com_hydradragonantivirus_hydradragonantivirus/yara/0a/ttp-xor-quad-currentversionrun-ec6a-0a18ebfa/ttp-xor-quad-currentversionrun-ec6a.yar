rule TTP_XOR_QUAD_CurrentVersionRun_ec6a {
  strings:
    $key_ec6a = { bf 05 [2] 9b 0b [2] b0 27 [2] 9e 05 [2] 8a 1e [2] 85 04 [2] 9b 19 [2] 99 18 [2] 82 1e [2] 9e 19 [2] 82 36 }

  condition:
    any of them
}