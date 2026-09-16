rule TTP_XOR_QUAD_CurrentVersionRun_ec34 {
  strings:
    $key_ec34 = { bf 5b [2] 9b 55 [2] b0 79 [2] 9e 5b [2] 8a 40 [2] 85 5a [2] 9b 47 [2] 99 46 [2] 82 40 [2] 9e 47 [2] 82 68 }

  condition:
    any of them
}