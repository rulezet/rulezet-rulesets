rule TTP_XOR_QUAD_CurrentVersionRun_956c {
  strings:
    $key_956c = { c6 03 [2] e2 0d [2] c9 21 [2] e7 03 [2] f3 18 [2] fc 02 [2] e2 1f [2] e0 1e [2] fb 18 [2] e7 1f [2] fb 30 }

  condition:
    any of them
}