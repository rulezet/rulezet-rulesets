rule TTP_XOR_QUAD_CurrentVersionRun_41a9 {
  strings:
    $key_41a9 = { 12 c6 [2] 36 c8 [2] 1d e4 [2] 33 c6 [2] 27 dd [2] 28 c7 [2] 36 da [2] 34 db [2] 2f dd [2] 33 da [2] 2f f5 }

  condition:
    any of them
}