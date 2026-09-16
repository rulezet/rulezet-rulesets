rule TTP_XOR_QUAD_CurrentVersionRun_9249 {
  strings:
    $key_9249 = { c1 26 [2] e5 28 [2] ce 04 [2] e0 26 [2] f4 3d [2] fb 27 [2] e5 3a [2] e7 3b [2] fc 3d [2] e0 3a [2] fc 15 }

  condition:
    any of them
}