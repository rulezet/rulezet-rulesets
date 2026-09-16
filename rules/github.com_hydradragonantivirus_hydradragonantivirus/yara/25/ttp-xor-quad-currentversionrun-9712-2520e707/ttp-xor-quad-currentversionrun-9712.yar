rule TTP_XOR_QUAD_CurrentVersionRun_9712 {
  strings:
    $key_9712 = { c4 7d [2] e0 73 [2] cb 5f [2] e5 7d [2] f1 66 [2] fe 7c [2] e0 61 [2] e2 60 [2] f9 66 [2] e5 61 [2] f9 4e }

  condition:
    any of them
}