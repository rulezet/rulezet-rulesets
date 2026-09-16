rule TTP_XOR_QUAD_CurrentVersionRun_e8a3 {
  strings:
    $key_e8a3 = { bb cc [2] 9f c2 [2] b4 ee [2] 9a cc [2] 8e d7 [2] 81 cd [2] 9f d0 [2] 9d d1 [2] 86 d7 [2] 9a d0 [2] 86 ff }

  condition:
    any of them
}