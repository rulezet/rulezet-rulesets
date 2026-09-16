rule TTP_XOR_QUAD_CurrentVersionRun_9274 {
  strings:
    $key_9274 = { c1 1b [2] e5 15 [2] ce 39 [2] e0 1b [2] f4 00 [2] fb 1a [2] e5 07 [2] e7 06 [2] fc 00 [2] e0 07 [2] fc 28 }

  condition:
    any of them
}