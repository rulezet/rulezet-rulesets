rule TTP_XOR_QUAD_CurrentVersionRun_73a3 {
  strings:
    $key_73a3 = { 20 cc [2] 04 c2 [2] 2f ee [2] 01 cc [2] 15 d7 [2] 1a cd [2] 04 d0 [2] 06 d1 [2] 1d d7 [2] 01 d0 [2] 1d ff }

  condition:
    any of them
}