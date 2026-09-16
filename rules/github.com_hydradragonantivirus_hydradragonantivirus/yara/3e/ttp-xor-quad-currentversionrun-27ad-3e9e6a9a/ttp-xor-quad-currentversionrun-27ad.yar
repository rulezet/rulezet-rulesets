rule TTP_XOR_QUAD_CurrentVersionRun_27ad {
  strings:
    $key_27ad = { 74 c2 [2] 50 cc [2] 7b e0 [2] 55 c2 [2] 41 d9 [2] 4e c3 [2] 50 de [2] 52 df [2] 49 d9 [2] 55 de [2] 49 f1 }

  condition:
    any of them
}