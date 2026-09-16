rule TTP_XOR_QUAD_CurrentVersionRun_b943 {
  strings:
    $key_b943 = { ea 2c [2] ce 22 [2] e5 0e [2] cb 2c [2] df 37 [2] d0 2d [2] ce 30 [2] cc 31 [2] d7 37 [2] cb 30 [2] d7 1f }

  condition:
    any of them
}