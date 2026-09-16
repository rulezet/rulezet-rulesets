rule TTP_XOR_QUAD_CurrentVersionRun_b9e5 {
  strings:
    $key_b9e5 = { ea 8a [2] ce 84 [2] e5 a8 [2] cb 8a [2] df 91 [2] d0 8b [2] ce 96 [2] cc 97 [2] d7 91 [2] cb 96 [2] d7 b9 }

  condition:
    any of them
}