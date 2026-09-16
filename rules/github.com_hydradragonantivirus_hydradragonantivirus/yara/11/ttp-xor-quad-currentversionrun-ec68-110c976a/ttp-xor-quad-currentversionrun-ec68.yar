rule TTP_XOR_QUAD_CurrentVersionRun_ec68 {
  strings:
    $key_ec68 = { bf 07 [2] 9b 09 [2] b0 25 [2] 9e 07 [2] 8a 1c [2] 85 06 [2] 9b 1b [2] 99 1a [2] 82 1c [2] 9e 1b [2] 82 34 }

  condition:
    any of them
}