rule TTP_XOR_QUAD_CurrentVersionRun_9276 {
  strings:
    $key_9276 = { c1 19 [2] e5 17 [2] ce 3b [2] e0 19 [2] f4 02 [2] fb 18 [2] e5 05 [2] e7 04 [2] fc 02 [2] e0 05 [2] fc 2a }

  condition:
    any of them
}