rule TTP_XOR_QUAD_CurrentVersionRun_9711 {
  strings:
    $key_9711 = { c4 7e [2] e0 70 [2] cb 5c [2] e5 7e [2] f1 65 [2] fe 7f [2] e0 62 [2] e2 63 [2] f9 65 [2] e5 62 [2] f9 4d }

  condition:
    any of them
}