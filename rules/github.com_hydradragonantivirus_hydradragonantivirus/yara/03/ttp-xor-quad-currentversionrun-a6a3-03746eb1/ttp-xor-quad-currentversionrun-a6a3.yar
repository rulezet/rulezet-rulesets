rule TTP_XOR_QUAD_CurrentVersionRun_a6a3 {
  strings:
    $key_a6a3 = { f5 cc [2] d1 c2 [2] fa ee [2] d4 cc [2] c0 d7 [2] cf cd [2] d1 d0 [2] d3 d1 [2] c8 d7 [2] d4 d0 [2] c8 ff }

  condition:
    any of them
}