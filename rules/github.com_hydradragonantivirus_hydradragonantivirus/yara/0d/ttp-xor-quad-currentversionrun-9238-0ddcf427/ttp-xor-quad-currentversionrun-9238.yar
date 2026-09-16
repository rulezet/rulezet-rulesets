rule TTP_XOR_QUAD_CurrentVersionRun_9238 {
  strings:
    $key_9238 = { c1 57 [2] e5 59 [2] ce 75 [2] e0 57 [2] f4 4c [2] fb 56 [2] e5 4b [2] e7 4a [2] fc 4c [2] e0 4b [2] fc 64 }

  condition:
    any of them
}