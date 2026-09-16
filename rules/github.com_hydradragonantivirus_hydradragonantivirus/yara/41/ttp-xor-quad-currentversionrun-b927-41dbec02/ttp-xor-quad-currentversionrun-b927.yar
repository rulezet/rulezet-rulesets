rule TTP_XOR_QUAD_CurrentVersionRun_b927 {
  strings:
    $key_b927 = { ea 48 [2] ce 46 [2] e5 6a [2] cb 48 [2] df 53 [2] d0 49 [2] ce 54 [2] cc 55 [2] d7 53 [2] cb 54 [2] d7 7b }

  condition:
    any of them
}