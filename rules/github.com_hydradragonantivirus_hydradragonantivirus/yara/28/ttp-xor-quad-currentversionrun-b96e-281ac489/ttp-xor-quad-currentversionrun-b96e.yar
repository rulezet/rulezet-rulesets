rule TTP_XOR_QUAD_CurrentVersionRun_b96e {
  strings:
    $key_b96e = { ea 01 [2] ce 0f [2] e5 23 [2] cb 01 [2] df 1a [2] d0 00 [2] ce 1d [2] cc 1c [2] d7 1a [2] cb 1d [2] d7 32 }

  condition:
    any of them
}