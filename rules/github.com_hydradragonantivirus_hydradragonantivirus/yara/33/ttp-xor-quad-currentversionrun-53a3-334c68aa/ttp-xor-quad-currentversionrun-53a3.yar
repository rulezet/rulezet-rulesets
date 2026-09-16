rule TTP_XOR_QUAD_CurrentVersionRun_53a3 {
  strings:
    $key_53a3 = { 00 cc [2] 24 c2 [2] 0f ee [2] 21 cc [2] 35 d7 [2] 3a cd [2] 24 d0 [2] 26 d1 [2] 3d d7 [2] 21 d0 [2] 3d ff }

  condition:
    any of them
}