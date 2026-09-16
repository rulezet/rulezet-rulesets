rule TTP_XOR_QUAD_CurrentVersionRun_31a9 {
  strings:
    $key_31a9 = { 62 c6 [2] 46 c8 [2] 6d e4 [2] 43 c6 [2] 57 dd [2] 58 c7 [2] 46 da [2] 44 db [2] 5f dd [2] 43 da [2] 5f f5 }

  condition:
    any of them
}