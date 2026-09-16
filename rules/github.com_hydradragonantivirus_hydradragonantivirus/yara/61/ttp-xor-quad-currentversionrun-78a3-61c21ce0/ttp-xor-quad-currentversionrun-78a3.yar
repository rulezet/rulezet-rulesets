rule TTP_XOR_QUAD_CurrentVersionRun_78a3 {
  strings:
    $key_78a3 = { 2b cc [2] 0f c2 [2] 24 ee [2] 0a cc [2] 1e d7 [2] 11 cd [2] 0f d0 [2] 0d d1 [2] 16 d7 [2] 0a d0 [2] 16 ff }

  condition:
    any of them
}