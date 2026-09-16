rule TTP_XOR_QUAD_CurrentVersionRun_bd91 {
  strings:
    $key_bd91 = { ee fe [2] ca f0 [2] e1 dc [2] cf fe [2] db e5 [2] d4 ff [2] ca e2 [2] c8 e3 [2] d3 e5 [2] cf e2 [2] d3 cd }

  condition:
    any of them
}