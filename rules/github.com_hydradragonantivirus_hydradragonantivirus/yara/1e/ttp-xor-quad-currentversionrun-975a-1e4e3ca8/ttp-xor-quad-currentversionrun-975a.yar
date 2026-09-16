rule TTP_XOR_QUAD_CurrentVersionRun_975a {
  strings:
    $key_975a = { c4 35 [2] e0 3b [2] cb 17 [2] e5 35 [2] f1 2e [2] fe 34 [2] e0 29 [2] e2 28 [2] f9 2e [2] e5 29 [2] f9 06 }

  condition:
    any of them
}