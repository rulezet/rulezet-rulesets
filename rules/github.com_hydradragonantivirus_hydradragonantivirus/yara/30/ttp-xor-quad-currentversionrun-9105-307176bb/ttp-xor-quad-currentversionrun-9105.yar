rule TTP_XOR_QUAD_CurrentVersionRun_9105 {
  strings:
    $key_9105 = { c2 6a [2] e6 64 [2] cd 48 [2] e3 6a [2] f7 71 [2] f8 6b [2] e6 76 [2] e4 77 [2] ff 71 [2] e3 76 [2] ff 59 }

  condition:
    any of them
}