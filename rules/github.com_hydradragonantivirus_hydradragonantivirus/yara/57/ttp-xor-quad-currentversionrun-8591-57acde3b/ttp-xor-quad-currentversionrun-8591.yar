rule TTP_XOR_QUAD_CurrentVersionRun_8591 {
  strings:
    $key_8591 = { d6 fe [2] f2 f0 [2] d9 dc [2] f7 fe [2] e3 e5 [2] ec ff [2] f2 e2 [2] f0 e3 [2] eb e5 [2] f7 e2 [2] eb cd }

  condition:
    any of them
}