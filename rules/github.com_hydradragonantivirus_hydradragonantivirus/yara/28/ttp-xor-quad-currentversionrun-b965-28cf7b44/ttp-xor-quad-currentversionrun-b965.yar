rule TTP_XOR_QUAD_CurrentVersionRun_b965 {
  strings:
    $key_b965 = { ea 0a [2] ce 04 [2] e5 28 [2] cb 0a [2] df 11 [2] d0 0b [2] ce 16 [2] cc 17 [2] d7 11 [2] cb 16 [2] d7 39 }

  condition:
    any of them
}