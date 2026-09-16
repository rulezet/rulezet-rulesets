rule TTP_XOR_QUAD_CurrentVersionRun_9290 {
  strings:
    $key_9290 = { c1 ff [2] e5 f1 [2] ce dd [2] e0 ff [2] f4 e4 [2] fb fe [2] e5 e3 [2] e7 e2 [2] fc e4 [2] e0 e3 [2] fc cc }

  condition:
    any of them
}