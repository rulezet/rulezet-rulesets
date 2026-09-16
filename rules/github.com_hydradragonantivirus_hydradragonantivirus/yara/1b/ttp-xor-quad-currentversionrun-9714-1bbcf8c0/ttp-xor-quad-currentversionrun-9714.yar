rule TTP_XOR_QUAD_CurrentVersionRun_9714 {
  strings:
    $key_9714 = { c4 7b [2] e0 75 [2] cb 59 [2] e5 7b [2] f1 60 [2] fe 7a [2] e0 67 [2] e2 66 [2] f9 60 [2] e5 67 [2] f9 48 }

  condition:
    any of them
}