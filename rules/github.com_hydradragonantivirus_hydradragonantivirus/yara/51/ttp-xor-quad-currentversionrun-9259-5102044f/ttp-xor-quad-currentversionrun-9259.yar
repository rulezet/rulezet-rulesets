rule TTP_XOR_QUAD_CurrentVersionRun_9259 {
  strings:
    $key_9259 = { c1 36 [2] e5 38 [2] ce 14 [2] e0 36 [2] f4 2d [2] fb 37 [2] e5 2a [2] e7 2b [2] fc 2d [2] e0 2a [2] fc 05 }

  condition:
    any of them
}