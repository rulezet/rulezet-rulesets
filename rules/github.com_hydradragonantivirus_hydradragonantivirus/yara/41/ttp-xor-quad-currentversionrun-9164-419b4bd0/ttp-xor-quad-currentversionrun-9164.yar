rule TTP_XOR_QUAD_CurrentVersionRun_9164 {
  strings:
    $key_9164 = { c2 0b [2] e6 05 [2] cd 29 [2] e3 0b [2] f7 10 [2] f8 0a [2] e6 17 [2] e4 16 [2] ff 10 [2] e3 17 [2] ff 38 }

  condition:
    any of them
}