rule TTP_XOR_QUAD_CurrentVersionRun_9593 {
  strings:
    $key_9593 = { c6 fc [2] e2 f2 [2] c9 de [2] e7 fc [2] f3 e7 [2] fc fd [2] e2 e0 [2] e0 e1 [2] fb e7 [2] e7 e0 [2] fb cf }

  condition:
    any of them
}