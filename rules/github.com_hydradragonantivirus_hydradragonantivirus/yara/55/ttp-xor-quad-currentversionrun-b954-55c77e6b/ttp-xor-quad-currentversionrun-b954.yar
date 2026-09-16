rule TTP_XOR_QUAD_CurrentVersionRun_b954 {
  strings:
    $key_b954 = { ea 3b [2] ce 35 [2] e5 19 [2] cb 3b [2] df 20 [2] d0 3a [2] ce 27 [2] cc 26 [2] d7 20 [2] cb 27 [2] d7 08 }

  condition:
    any of them
}