rule TTP_XOR_QUAD_CurrentVersionRun_9511 {
  strings:
    $key_9511 = { c6 7e [2] e2 70 [2] c9 5c [2] e7 7e [2] f3 65 [2] fc 7f [2] e2 62 [2] e0 63 [2] fb 65 [2] e7 62 [2] fb 4d }

  condition:
    any of them
}