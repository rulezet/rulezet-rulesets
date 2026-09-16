rule TTP_XOR_QUAD_CurrentVersionRun_f3a3 {
  strings:
    $key_f3a3 = { a0 cc [2] 84 c2 [2] af ee [2] 81 cc [2] 95 d7 [2] 9a cd [2] 84 d0 [2] 86 d1 [2] 9d d7 [2] 81 d0 [2] 9d ff }

  condition:
    any of them
}