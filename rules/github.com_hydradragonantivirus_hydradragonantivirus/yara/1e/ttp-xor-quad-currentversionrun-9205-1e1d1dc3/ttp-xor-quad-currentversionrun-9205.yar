rule TTP_XOR_QUAD_CurrentVersionRun_9205 {
  strings:
    $key_9205 = { c1 6a [2] e5 64 [2] ce 48 [2] e0 6a [2] f4 71 [2] fb 6b [2] e5 76 [2] e7 77 [2] fc 71 [2] e0 76 [2] fc 59 }

  condition:
    any of them
}