rule TTP_XOR_QUAD_CurrentVersionRun_b919 {
  strings:
    $key_b919 = { ea 76 [2] ce 78 [2] e5 54 [2] cb 76 [2] df 6d [2] d0 77 [2] ce 6a [2] cc 6b [2] d7 6d [2] cb 6a [2] d7 45 }

  condition:
    any of them
}