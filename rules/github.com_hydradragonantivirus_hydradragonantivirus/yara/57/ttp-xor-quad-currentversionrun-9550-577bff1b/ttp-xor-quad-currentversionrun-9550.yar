rule TTP_XOR_QUAD_CurrentVersionRun_9550 {
  strings:
    $key_9550 = { c6 3f [2] e2 31 [2] c9 1d [2] e7 3f [2] f3 24 [2] fc 3e [2] e2 23 [2] e0 22 [2] fb 24 [2] e7 23 [2] fb 0c }

  condition:
    any of them
}