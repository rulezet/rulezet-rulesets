rule TTP_XOR_QUAD_CurrentVersionRun_9505 {
  strings:
    $key_9505 = { c6 6a [2] e2 64 [2] c9 48 [2] e7 6a [2] f3 71 [2] fc 6b [2] e2 76 [2] e0 77 [2] fb 71 [2] e7 76 [2] fb 59 }

  condition:
    any of them
}