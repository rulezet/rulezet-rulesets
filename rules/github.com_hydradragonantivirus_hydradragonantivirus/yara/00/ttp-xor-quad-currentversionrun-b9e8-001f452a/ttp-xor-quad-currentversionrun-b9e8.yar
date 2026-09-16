rule TTP_XOR_QUAD_CurrentVersionRun_b9e8 {
  strings:
    $key_b9e8 = { ea 87 [2] ce 89 [2] e5 a5 [2] cb 87 [2] df 9c [2] d0 86 [2] ce 9b [2] cc 9a [2] d7 9c [2] cb 9b [2] d7 b4 }

  condition:
    any of them
}