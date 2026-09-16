rule TTP_XOR_QUAD_CurrentVersionRun_a891 {
  strings:
    $key_a891 = { fb fe [2] df f0 [2] f4 dc [2] da fe [2] ce e5 [2] c1 ff [2] df e2 [2] dd e3 [2] c6 e5 [2] da e2 [2] c6 cd }

  condition:
    any of them
}