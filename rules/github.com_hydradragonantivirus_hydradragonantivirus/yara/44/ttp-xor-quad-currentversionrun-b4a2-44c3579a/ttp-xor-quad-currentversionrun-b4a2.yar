rule TTP_XOR_QUAD_CurrentVersionRun_b4a2 {
  strings:
    $key_b4a2 = { e7 cd [2] c3 c3 [2] e8 ef [2] c6 cd [2] d2 d6 [2] dd cc [2] c3 d1 [2] c1 d0 [2] da d6 [2] c6 d1 [2] da fe }

  condition:
    any of them
}