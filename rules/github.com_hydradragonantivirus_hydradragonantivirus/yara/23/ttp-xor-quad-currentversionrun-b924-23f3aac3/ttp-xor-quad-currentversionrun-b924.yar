rule TTP_XOR_QUAD_CurrentVersionRun_b924 {
  strings:
    $key_b924 = { ea 4b [2] ce 45 [2] e5 69 [2] cb 4b [2] df 50 [2] d0 4a [2] ce 57 [2] cc 56 [2] d7 50 [2] cb 57 [2] d7 78 }

  condition:
    any of them
}