rule TTP_XOR_QUAD_CurrentVersionRun_af91 {
  strings:
    $key_af91 = { fc fe [2] d8 f0 [2] f3 dc [2] dd fe [2] c9 e5 [2] c6 ff [2] d8 e2 [2] da e3 [2] c1 e5 [2] dd e2 [2] c1 cd }

  condition:
    any of them
}