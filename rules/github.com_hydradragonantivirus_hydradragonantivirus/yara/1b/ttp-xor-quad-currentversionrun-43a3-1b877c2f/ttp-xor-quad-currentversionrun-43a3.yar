rule TTP_XOR_QUAD_CurrentVersionRun_43a3 {
  strings:
    $key_43a3 = { 10 cc [2] 34 c2 [2] 1f ee [2] 31 cc [2] 25 d7 [2] 2a cd [2] 34 d0 [2] 36 d1 [2] 2d d7 [2] 31 d0 [2] 2d ff }

  condition:
    any of them
}