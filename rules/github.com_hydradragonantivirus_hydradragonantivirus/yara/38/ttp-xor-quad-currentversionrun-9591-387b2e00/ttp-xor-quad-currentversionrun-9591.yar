rule TTP_XOR_QUAD_CurrentVersionRun_9591 {
  strings:
    $key_9591 = { c6 fe [2] e2 f0 [2] c9 dc [2] e7 fe [2] f3 e5 [2] fc ff [2] e2 e2 [2] e0 e3 [2] fb e5 [2] e7 e2 [2] fb cd }

  condition:
    any of them
}