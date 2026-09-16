rule TTP_XOR_QUAD_CurrentVersionRun_9571 {
  strings:
    $key_9571 = { c6 1e [2] e2 10 [2] c9 3c [2] e7 1e [2] f3 05 [2] fc 1f [2] e2 02 [2] e0 03 [2] fb 05 [2] e7 02 [2] fb 2d }

  condition:
    any of them
}