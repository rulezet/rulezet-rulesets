rule TTP_XOR_QUAD_CurrentVersionRun_bda2 {
  strings:
    $key_bda2 = { ee cd [2] ca c3 [2] e1 ef [2] cf cd [2] db d6 [2] d4 cc [2] ca d1 [2] c8 d0 [2] d3 d6 [2] cf d1 [2] d3 fe }

  condition:
    any of them
}