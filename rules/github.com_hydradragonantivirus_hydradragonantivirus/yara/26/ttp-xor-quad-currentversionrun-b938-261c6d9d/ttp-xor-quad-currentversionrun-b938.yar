rule TTP_XOR_QUAD_CurrentVersionRun_b938 {
  strings:
    $key_b938 = { ea 57 [2] ce 59 [2] e5 75 [2] cb 57 [2] df 4c [2] d0 56 [2] ce 4b [2] cc 4a [2] d7 4c [2] cb 4b [2] d7 64 }

  condition:
    any of them
}