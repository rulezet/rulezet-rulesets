rule TTP_XOR_QUAD_CurrentVersionRun_9204 {
  strings:
    $key_9204 = { c1 6b [2] e5 65 [2] ce 49 [2] e0 6b [2] f4 70 [2] fb 6a [2] e5 77 [2] e7 76 [2] fc 70 [2] e0 77 [2] fc 58 }

  condition:
    any of them
}