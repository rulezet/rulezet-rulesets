rule TTP_XOR_QUAD_CurrentVersionRun_977b {
  strings:
    $key_977b = { c4 14 [2] e0 1a [2] cb 36 [2] e5 14 [2] f1 0f [2] fe 15 [2] e0 08 [2] e2 09 [2] f9 0f [2] e5 08 [2] f9 27 }

  condition:
    any of them
}