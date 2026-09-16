rule TTP_XOR_QUAD_CurrentVersionRun_9145 {
  strings:
    $key_9145 = { c2 2a [2] e6 24 [2] cd 08 [2] e3 2a [2] f7 31 [2] f8 2b [2] e6 36 [2] e4 37 [2] ff 31 [2] e3 36 [2] ff 19 }

  condition:
    any of them
}