rule TTP_XOR_QUAD_CurrentVersionRun_07a9 {
  strings:
    $key_07a9 = { 54 c6 [2] 70 c8 [2] 5b e4 [2] 75 c6 [2] 61 dd [2] 6e c7 [2] 70 da [2] 72 db [2] 69 dd [2] 75 da [2] 69 f5 }

  condition:
    any of them
}