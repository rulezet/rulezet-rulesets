rule TTP_XOR_QUAD_CurrentVersionRun_9021 {
  strings:
    $key_9021 = { c3 4e [2] e7 40 [2] cc 6c [2] e2 4e [2] f6 55 [2] f9 4f [2] e7 52 [2] e5 53 [2] fe 55 [2] e2 52 [2] fe 7d }

  condition:
    any of them
}