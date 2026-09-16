rule TTP_XOR_QUAD_CurrentVersionRun_9263 {
  strings:
    $key_9263 = { c1 0c [2] e5 02 [2] ce 2e [2] e0 0c [2] f4 17 [2] fb 0d [2] e5 10 [2] e7 11 [2] fc 17 [2] e0 10 [2] fc 3f }

  condition:
    any of them
}