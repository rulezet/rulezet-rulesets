rule TTP_XOR_QUAD_CurrentVersionRun_9169 {
  strings:
    $key_9169 = { c2 06 [2] e6 08 [2] cd 24 [2] e3 06 [2] f7 1d [2] f8 07 [2] e6 1a [2] e4 1b [2] ff 1d [2] e3 1a [2] ff 35 }

  condition:
    any of them
}