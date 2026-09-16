rule TTP_XOR_QUAD_CurrentVersionRun_9739 {
  strings:
    $key_9739 = { c4 56 [2] e0 58 [2] cb 74 [2] e5 56 [2] f1 4d [2] fe 57 [2] e0 4a [2] e2 4b [2] f9 4d [2] e5 4a [2] f9 65 }

  condition:
    any of them
}