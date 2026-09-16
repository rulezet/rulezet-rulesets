rule TTP_XOR_QUAD_CurrentVersionRun_43bb {
  strings:
    $key_43bb = { 10 d4 [2] 34 da [2] 1f f6 [2] 31 d4 [2] 25 cf [2] 2a d5 [2] 34 c8 [2] 36 c9 [2] 2d cf [2] 31 c8 [2] 2d e7 }

  condition:
    any of them
}