rule TTP_XOR_QUAD_CurrentVersionRun_33bb {
  strings:
    $key_33bb = { 60 d4 [2] 44 da [2] 6f f6 [2] 41 d4 [2] 55 cf [2] 5a d5 [2] 44 c8 [2] 46 c9 [2] 5d cf [2] 41 c8 [2] 5d e7 }

  condition:
    any of them
}