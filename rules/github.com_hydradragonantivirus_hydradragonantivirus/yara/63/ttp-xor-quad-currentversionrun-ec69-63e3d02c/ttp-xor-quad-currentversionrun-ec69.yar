rule TTP_XOR_QUAD_CurrentVersionRun_ec69 {
  strings:
    $key_ec69 = { bf 06 [2] 9b 08 [2] b0 24 [2] 9e 06 [2] 8a 1d [2] 85 07 [2] 9b 1a [2] 99 1b [2] 82 1d [2] 9e 1a [2] 82 35 }

  condition:
    any of them
}