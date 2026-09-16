rule TTP_XOR_QUAD_CurrentVersionRun_b9f8 {
  strings:
    $key_b9f8 = { ea 97 [2] ce 99 [2] e5 b5 [2] cb 97 [2] df 8c [2] d0 96 [2] ce 8b [2] cc 8a [2] d7 8c [2] cb 8b [2] d7 a4 }

  condition:
    any of them
}