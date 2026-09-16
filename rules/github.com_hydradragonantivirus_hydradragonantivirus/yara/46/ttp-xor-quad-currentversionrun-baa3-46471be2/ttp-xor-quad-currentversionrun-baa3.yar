rule TTP_XOR_QUAD_CurrentVersionRun_baa3 {
  strings:
    $key_baa3 = { e9 cc [2] cd c2 [2] e6 ee [2] c8 cc [2] dc d7 [2] d3 cd [2] cd d0 [2] cf d1 [2] d4 d7 [2] c8 d0 [2] d4 ff }

  condition:
    any of them
}