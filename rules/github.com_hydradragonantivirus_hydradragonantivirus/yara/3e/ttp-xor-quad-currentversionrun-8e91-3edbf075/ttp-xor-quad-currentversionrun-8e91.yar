rule TTP_XOR_QUAD_CurrentVersionRun_8e91 {
  strings:
    $key_8e91 = { dd fe [2] f9 f0 [2] d2 dc [2] fc fe [2] e8 e5 [2] e7 ff [2] f9 e2 [2] fb e3 [2] e0 e5 [2] fc e2 [2] e0 cd }

  condition:
    any of them
}