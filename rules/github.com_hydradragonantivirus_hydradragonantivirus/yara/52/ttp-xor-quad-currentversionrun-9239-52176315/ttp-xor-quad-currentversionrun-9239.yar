rule TTP_XOR_QUAD_CurrentVersionRun_9239 {
  strings:
    $key_9239 = { c1 56 [2] e5 58 [2] ce 74 [2] e0 56 [2] f4 4d [2] fb 57 [2] e5 4a [2] e7 4b [2] fc 4d [2] e0 4a [2] fc 65 }

  condition:
    any of them
}