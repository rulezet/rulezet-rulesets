rule TTP_XOR_QUAD_CurrentVersionRun_b94b {
  strings:
    $key_b94b = { ea 24 [2] ce 2a [2] e5 06 [2] cb 24 [2] df 3f [2] d0 25 [2] ce 38 [2] cc 39 [2] d7 3f [2] cb 38 [2] d7 17 }

  condition:
    any of them
}