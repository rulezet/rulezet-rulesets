rule TTP_XOR_QUAD_CurrentVersionRun_9530 {
  strings:
    $key_9530 = { c6 5f [2] e2 51 [2] c9 7d [2] e7 5f [2] f3 44 [2] fc 5e [2] e2 43 [2] e0 42 [2] fb 44 [2] e7 43 [2] fb 6c }

  condition:
    any of them
}