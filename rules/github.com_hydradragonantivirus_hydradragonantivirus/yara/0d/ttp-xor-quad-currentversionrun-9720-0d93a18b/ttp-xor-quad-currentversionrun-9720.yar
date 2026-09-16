rule TTP_XOR_QUAD_CurrentVersionRun_9720 {
  strings:
    $key_9720 = { c4 4f [2] e0 41 [2] cb 6d [2] e5 4f [2] f1 54 [2] fe 4e [2] e0 53 [2] e2 52 [2] f9 54 [2] e5 53 [2] f9 7c }

  condition:
    any of them
}