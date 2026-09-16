rule TTP_XOR_QUAD_CurrentVersionRun_b9e6 {
  strings:
    $key_b9e6 = { ea 89 [2] ce 87 [2] e5 ab [2] cb 89 [2] df 92 [2] d0 88 [2] ce 95 [2] cc 94 [2] d7 92 [2] cb 95 [2] d7 ba }

  condition:
    any of them
}