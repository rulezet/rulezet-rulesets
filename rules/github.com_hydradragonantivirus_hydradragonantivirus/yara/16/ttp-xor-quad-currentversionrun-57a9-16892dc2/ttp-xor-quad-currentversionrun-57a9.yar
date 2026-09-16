rule TTP_XOR_QUAD_CurrentVersionRun_57a9 {
  strings:
    $key_57a9 = { 04 c6 [2] 20 c8 [2] 0b e4 [2] 25 c6 [2] 31 dd [2] 3e c7 [2] 20 da [2] 22 db [2] 39 dd [2] 25 da [2] 39 f5 }

  condition:
    any of them
}