rule TTP_XOR_QUAD_CurrentVersionRun_9218 {
  strings:
    $key_9218 = { c1 77 [2] e5 79 [2] ce 55 [2] e0 77 [2] f4 6c [2] fb 76 [2] e5 6b [2] e7 6a [2] fc 6c [2] e0 6b [2] fc 44 }

  condition:
    any of them
}