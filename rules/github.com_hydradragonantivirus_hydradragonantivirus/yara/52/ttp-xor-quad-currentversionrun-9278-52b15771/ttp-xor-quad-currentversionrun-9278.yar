rule TTP_XOR_QUAD_CurrentVersionRun_9278 {
  strings:
    $key_9278 = { c1 17 [2] e5 19 [2] ce 35 [2] e0 17 [2] f4 0c [2] fb 16 [2] e5 0b [2] e7 0a [2] fc 0c [2] e0 0b [2] fc 24 }

  condition:
    any of them
}