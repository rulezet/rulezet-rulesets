rule TTP_XOR_QUAD_CurrentVersionRun_9214 {
  strings:
    $key_9214 = { c1 7b [2] e5 75 [2] ce 59 [2] e0 7b [2] f4 60 [2] fb 7a [2] e5 67 [2] e7 66 [2] fc 60 [2] e0 67 [2] fc 48 }

  condition:
    any of them
}