rule TTP_XOR_QUAD_CurrentVersionRun_9203 {
  strings:
    $key_9203 = { c1 6c [2] e5 62 [2] ce 4e [2] e0 6c [2] f4 77 [2] fb 6d [2] e5 70 [2] e7 71 [2] fc 77 [2] e0 70 [2] fc 5f }

  condition:
    any of them
}