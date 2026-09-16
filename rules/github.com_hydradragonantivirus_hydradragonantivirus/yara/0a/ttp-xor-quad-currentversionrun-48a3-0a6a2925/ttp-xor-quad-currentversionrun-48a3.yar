rule TTP_XOR_QUAD_CurrentVersionRun_48a3 {
  strings:
    $key_48a3 = { 1b cc [2] 3f c2 [2] 14 ee [2] 3a cc [2] 2e d7 [2] 21 cd [2] 3f d0 [2] 3d d1 [2] 26 d7 [2] 3a d0 [2] 26 ff }

  condition:
    any of them
}