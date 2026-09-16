rule TTP_XOR_QUAD_CurrentVersionRun_f8a3 {
  strings:
    $key_f8a3 = { ab cc [2] 8f c2 [2] a4 ee [2] 8a cc [2] 9e d7 [2] 91 cd [2] 8f d0 [2] 8d d1 [2] 96 d7 [2] 8a d0 [2] 96 ff }

  condition:
    any of them
}