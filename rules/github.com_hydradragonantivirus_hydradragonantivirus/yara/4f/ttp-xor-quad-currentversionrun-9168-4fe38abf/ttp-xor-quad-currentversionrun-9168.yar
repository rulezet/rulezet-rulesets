rule TTP_XOR_QUAD_CurrentVersionRun_9168 {
  strings:
    $key_9168 = { c2 07 [2] e6 09 [2] cd 25 [2] e3 07 [2] f7 1c [2] f8 06 [2] e6 1b [2] e4 1a [2] ff 1c [2] e3 1b [2] ff 34 }

  condition:
    any of them
}