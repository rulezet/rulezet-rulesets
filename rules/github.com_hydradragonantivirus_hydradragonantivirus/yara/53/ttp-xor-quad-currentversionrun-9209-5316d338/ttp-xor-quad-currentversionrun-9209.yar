rule TTP_XOR_QUAD_CurrentVersionRun_9209 {
  strings:
    $key_9209 = { c1 66 [2] e5 68 [2] ce 44 [2] e0 66 [2] f4 7d [2] fb 67 [2] e5 7a [2] e7 7b [2] fc 7d [2] e0 7a [2] fc 55 }

  condition:
    any of them
}