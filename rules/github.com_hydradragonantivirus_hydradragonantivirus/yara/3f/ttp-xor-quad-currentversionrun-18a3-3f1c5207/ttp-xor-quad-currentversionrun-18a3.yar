rule TTP_XOR_QUAD_CurrentVersionRun_18a3 {
  strings:
    $key_18a3 = { 4b cc [2] 6f c2 [2] 44 ee [2] 6a cc [2] 7e d7 [2] 71 cd [2] 6f d0 [2] 6d d1 [2] 76 d7 [2] 6a d0 [2] 76 ff }

  condition:
    any of them
}