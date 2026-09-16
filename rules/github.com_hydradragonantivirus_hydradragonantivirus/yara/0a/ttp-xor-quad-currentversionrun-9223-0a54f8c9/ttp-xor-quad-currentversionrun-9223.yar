rule TTP_XOR_QUAD_CurrentVersionRun_9223 {
  strings:
    $key_9223 = { c1 4c [2] e5 42 [2] ce 6e [2] e0 4c [2] f4 57 [2] fb 4d [2] e5 50 [2] e7 51 [2] fc 57 [2] e0 50 [2] fc 7f }

  condition:
    any of them
}