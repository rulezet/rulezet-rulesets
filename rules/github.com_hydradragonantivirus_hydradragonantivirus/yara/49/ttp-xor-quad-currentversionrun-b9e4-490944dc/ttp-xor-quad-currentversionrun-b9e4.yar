rule TTP_XOR_QUAD_CurrentVersionRun_b9e4 {
  strings:
    $key_b9e4 = { ea 8b [2] ce 85 [2] e5 a9 [2] cb 8b [2] df 90 [2] d0 8a [2] ce 97 [2] cc 96 [2] d7 90 [2] cb 97 [2] d7 b8 }

  condition:
    any of them
}