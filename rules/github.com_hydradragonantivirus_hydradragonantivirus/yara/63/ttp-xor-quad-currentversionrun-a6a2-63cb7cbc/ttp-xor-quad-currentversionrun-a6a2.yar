rule TTP_XOR_QUAD_CurrentVersionRun_a6a2 {
  strings:
    $key_a6a2 = { f5 cd [2] d1 c3 [2] fa ef [2] d4 cd [2] c0 d6 [2] cf cc [2] d1 d1 [2] d3 d0 [2] c8 d6 [2] d4 d1 [2] c8 fe }

  condition:
    any of them
}