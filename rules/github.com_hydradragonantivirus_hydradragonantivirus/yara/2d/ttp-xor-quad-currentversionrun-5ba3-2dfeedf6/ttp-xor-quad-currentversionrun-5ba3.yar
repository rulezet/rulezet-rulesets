rule TTP_XOR_QUAD_CurrentVersionRun_5ba3 {
  strings:
    $key_5ba3 = { 08 cc [2] 2c c2 [2] 07 ee [2] 29 cc [2] 3d d7 [2] 32 cd [2] 2c d0 [2] 2e d1 [2] 35 d7 [2] 29 d0 [2] 35 ff }

  condition:
    any of them
}