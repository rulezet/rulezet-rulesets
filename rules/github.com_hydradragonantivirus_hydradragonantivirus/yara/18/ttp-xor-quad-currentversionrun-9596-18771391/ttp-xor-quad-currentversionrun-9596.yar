rule TTP_XOR_QUAD_CurrentVersionRun_9596 {
  strings:
    $key_9596 = { c6 f9 [2] e2 f7 [2] c9 db [2] e7 f9 [2] f3 e2 [2] fc f8 [2] e2 e5 [2] e0 e4 [2] fb e2 [2] e7 e5 [2] fb ca }

  condition:
    any of them
}