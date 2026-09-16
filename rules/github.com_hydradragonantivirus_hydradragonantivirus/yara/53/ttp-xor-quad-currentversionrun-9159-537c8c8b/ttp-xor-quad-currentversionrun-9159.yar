rule TTP_XOR_QUAD_CurrentVersionRun_9159 {
  strings:
    $key_9159 = { c2 36 [2] e6 38 [2] cd 14 [2] e3 36 [2] f7 2d [2] f8 37 [2] e6 2a [2] e4 2b [2] ff 2d [2] e3 2a [2] ff 05 }

  condition:
    any of them
}