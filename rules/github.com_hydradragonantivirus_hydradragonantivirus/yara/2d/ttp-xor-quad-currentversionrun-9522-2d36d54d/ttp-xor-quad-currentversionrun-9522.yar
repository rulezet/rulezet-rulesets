rule TTP_XOR_QUAD_CurrentVersionRun_9522 {
  strings:
    $key_9522 = { c6 4d [2] e2 43 [2] c9 6f [2] e7 4d [2] f3 56 [2] fc 4c [2] e2 51 [2] e0 50 [2] fb 56 [2] e7 51 [2] fb 7e }

  condition:
    any of them
}