rule TTP_XOR_QUAD_CurrentVersionRun_b5a2 {
  strings:
    $key_b5a2 = { e6 cd [2] c2 c3 [2] e9 ef [2] c7 cd [2] d3 d6 [2] dc cc [2] c2 d1 [2] c0 d0 [2] db d6 [2] c7 d1 [2] db fe }

  condition:
    any of them
}