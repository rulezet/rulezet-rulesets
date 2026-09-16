rule TTP_XOR_QUAD_CurrentVersionRun_b977 {
  strings:
    $key_b977 = { ea 18 [2] ce 16 [2] e5 3a [2] cb 18 [2] df 03 [2] d0 19 [2] ce 04 [2] cc 05 [2] d7 03 [2] cb 04 [2] d7 2b }

  condition:
    any of them
}