rule TTP_XOR_QUAD_CurrentVersionRun_b979 {
  strings:
    $key_b979 = { ea 16 [2] ce 18 [2] e5 34 [2] cb 16 [2] df 0d [2] d0 17 [2] ce 0a [2] cc 0b [2] d7 0d [2] cb 0a [2] d7 25 }

  condition:
    any of them
}