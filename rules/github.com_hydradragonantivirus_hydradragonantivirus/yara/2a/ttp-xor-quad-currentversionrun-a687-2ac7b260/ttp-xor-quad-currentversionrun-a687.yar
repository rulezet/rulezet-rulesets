rule TTP_XOR_QUAD_CurrentVersionRun_a687 {
  strings:
    $key_a687 = { f5 e8 [2] d1 e6 [2] fa ca [2] d4 e8 [2] c0 f3 [2] cf e9 [2] d1 f4 [2] d3 f5 [2] c8 f3 [2] d4 f4 [2] c8 db }

  condition:
    any of them
}