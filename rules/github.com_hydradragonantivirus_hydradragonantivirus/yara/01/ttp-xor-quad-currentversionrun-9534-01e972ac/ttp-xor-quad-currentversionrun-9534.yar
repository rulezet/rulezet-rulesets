rule TTP_XOR_QUAD_CurrentVersionRun_9534 {
  strings:
    $key_9534 = { c6 5b [2] e2 55 [2] c9 79 [2] e7 5b [2] f3 40 [2] fc 5a [2] e2 47 [2] e0 46 [2] fb 40 [2] e7 47 [2] fb 68 }

  condition:
    any of them
}