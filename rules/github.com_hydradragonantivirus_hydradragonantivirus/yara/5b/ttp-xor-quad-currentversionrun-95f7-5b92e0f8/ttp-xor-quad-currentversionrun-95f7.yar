rule TTP_XOR_QUAD_CurrentVersionRun_95f7 {
  strings:
    $key_95f7 = { c6 98 [2] e2 96 [2] c9 ba [2] e7 98 [2] f3 83 [2] fc 99 [2] e2 84 [2] e0 85 [2] fb 83 [2] e7 84 [2] fb ab }

  condition:
    any of them
}