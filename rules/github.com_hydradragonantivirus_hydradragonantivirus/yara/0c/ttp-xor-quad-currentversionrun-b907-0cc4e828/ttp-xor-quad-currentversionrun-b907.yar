rule TTP_XOR_QUAD_CurrentVersionRun_b907 {
  strings:
    $key_b907 = { ea 68 [2] ce 66 [2] e5 4a [2] cb 68 [2] df 73 [2] d0 69 [2] ce 74 [2] cc 75 [2] d7 73 [2] cb 74 [2] d7 5b }

  condition:
    any of them
}