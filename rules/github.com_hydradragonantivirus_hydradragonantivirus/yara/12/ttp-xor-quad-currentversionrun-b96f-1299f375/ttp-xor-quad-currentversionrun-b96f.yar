rule TTP_XOR_QUAD_CurrentVersionRun_b96f {
  strings:
    $key_b96f = { ea 00 [2] ce 0e [2] e5 22 [2] cb 00 [2] df 1b [2] d0 01 [2] ce 1c [2] cc 1d [2] d7 1b [2] cb 1c [2] d7 33 }

  condition:
    any of them
}