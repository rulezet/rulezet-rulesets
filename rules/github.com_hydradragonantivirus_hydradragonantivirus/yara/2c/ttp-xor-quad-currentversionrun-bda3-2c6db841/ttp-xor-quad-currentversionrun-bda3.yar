rule TTP_XOR_QUAD_CurrentVersionRun_bda3 {
  strings:
    $key_bda3 = { ee cc [2] ca c2 [2] e1 ee [2] cf cc [2] db d7 [2] d4 cd [2] ca d0 [2] c8 d1 [2] d3 d7 [2] cf d0 [2] d3 ff }

  condition:
    any of them
}