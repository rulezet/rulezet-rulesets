rule TTP_XOR_QUAD_CurrentVersionRun_9708 {
  strings:
    $key_9708 = { c4 67 [2] e0 69 [2] cb 45 [2] e5 67 [2] f1 7c [2] fe 66 [2] e0 7b [2] e2 7a [2] f9 7c [2] e5 7b [2] f9 54 }

  condition:
    any of them
}