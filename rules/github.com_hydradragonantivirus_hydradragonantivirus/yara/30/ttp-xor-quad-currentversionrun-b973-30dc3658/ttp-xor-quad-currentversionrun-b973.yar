rule TTP_XOR_QUAD_CurrentVersionRun_b973 {
  strings:
    $key_b973 = { ea 1c [2] ce 12 [2] e5 3e [2] cb 1c [2] df 07 [2] d0 1d [2] ce 00 [2] cc 01 [2] d7 07 [2] cb 00 [2] d7 2f }

  condition:
    any of them
}