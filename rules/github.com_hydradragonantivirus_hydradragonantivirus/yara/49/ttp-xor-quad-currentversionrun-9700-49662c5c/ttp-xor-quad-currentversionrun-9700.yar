rule TTP_XOR_QUAD_CurrentVersionRun_9700 {
  strings:
    $key_9700 = { c4 6f [2] e0 61 [2] cb 4d [2] e5 6f [2] f1 74 [2] fe 6e [2] e0 73 [2] e2 72 [2] f9 74 [2] e5 73 [2] f9 5c }

  condition:
    any of them
}