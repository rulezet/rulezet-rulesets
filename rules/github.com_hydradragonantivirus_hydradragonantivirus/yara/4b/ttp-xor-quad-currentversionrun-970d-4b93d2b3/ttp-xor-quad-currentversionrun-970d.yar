rule TTP_XOR_QUAD_CurrentVersionRun_970d {
  strings:
    $key_970d = { c4 62 [2] e0 6c [2] cb 40 [2] e5 62 [2] f1 79 [2] fe 63 [2] e0 7e [2] e2 7f [2] f9 79 [2] e5 7e [2] f9 51 }

  condition:
    any of them
}