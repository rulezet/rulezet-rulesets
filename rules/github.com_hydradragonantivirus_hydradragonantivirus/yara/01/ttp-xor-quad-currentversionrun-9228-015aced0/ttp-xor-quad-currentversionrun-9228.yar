rule TTP_XOR_QUAD_CurrentVersionRun_9228 {
  strings:
    $key_9228 = { c1 47 [2] e5 49 [2] ce 65 [2] e0 47 [2] f4 5c [2] fb 46 [2] e5 5b [2] e7 5a [2] fc 5c [2] e0 5b [2] fc 74 }

  condition:
    any of them
}