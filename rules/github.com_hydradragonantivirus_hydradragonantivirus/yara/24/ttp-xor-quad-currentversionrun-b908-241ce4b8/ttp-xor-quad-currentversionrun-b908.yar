rule TTP_XOR_QUAD_CurrentVersionRun_b908 {
  strings:
    $key_b908 = { ea 67 [2] ce 69 [2] e5 45 [2] cb 67 [2] df 7c [2] d0 66 [2] ce 7b [2] cc 7a [2] d7 7c [2] cb 7b [2] d7 54 }

  condition:
    any of them
}