rule TTP_XOR_QUAD_CurrentVersionRun_b948 {
  strings:
    $key_b948 = { ea 27 [2] ce 29 [2] e5 05 [2] cb 27 [2] df 3c [2] d0 26 [2] ce 3b [2] cc 3a [2] d7 3c [2] cb 3b [2] d7 14 }

  condition:
    any of them
}