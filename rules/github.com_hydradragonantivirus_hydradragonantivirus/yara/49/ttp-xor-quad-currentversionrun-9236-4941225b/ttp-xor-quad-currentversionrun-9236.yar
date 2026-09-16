rule TTP_XOR_QUAD_CurrentVersionRun_9236 {
  strings:
    $key_9236 = { c1 59 [2] e5 57 [2] ce 7b [2] e0 59 [2] f4 42 [2] fb 58 [2] e5 45 [2] e7 44 [2] fc 42 [2] e0 45 [2] fc 6a }

  condition:
    any of them
}