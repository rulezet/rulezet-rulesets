rule TTP_XOR_QUAD_CurrentVersionRun_9291 {
  strings:
    $key_9291 = { c1 fe [2] e5 f0 [2] ce dc [2] e0 fe [2] f4 e5 [2] fb ff [2] e5 e2 [2] e7 e3 [2] fc e5 [2] e0 e2 [2] fc cd }

  condition:
    any of them
}