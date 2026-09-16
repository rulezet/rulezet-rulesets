rule TTP_XOR_QUAD_CurrentVersionRun_ec29 {
  strings:
    $key_ec29 = { bf 46 [2] 9b 48 [2] b0 64 [2] 9e 46 [2] 8a 5d [2] 85 47 [2] 9b 5a [2] 99 5b [2] 82 5d [2] 9e 5a [2] 82 75 }

  condition:
    any of them
}