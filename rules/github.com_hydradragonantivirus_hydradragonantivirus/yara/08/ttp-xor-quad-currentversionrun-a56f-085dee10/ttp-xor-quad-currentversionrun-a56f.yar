rule TTP_XOR_QUAD_CurrentVersionRun_a56f {
  strings:
    $key_a56f = { f6 00 [2] d2 0e [2] f9 22 [2] d7 00 [2] c3 1b [2] cc 01 [2] d2 1c [2] d0 1d [2] cb 1b [2] d7 1c [2] cb 33 }

  condition:
    any of them
}