rule TTP_XOR_QUAD_CurrentVersionRun_b947 {
  strings:
    $key_b947 = { ea 28 [2] ce 26 [2] e5 0a [2] cb 28 [2] df 33 [2] d0 29 [2] ce 34 [2] cc 35 [2] d7 33 [2] cb 34 [2] d7 1b }

  condition:
    any of them
}