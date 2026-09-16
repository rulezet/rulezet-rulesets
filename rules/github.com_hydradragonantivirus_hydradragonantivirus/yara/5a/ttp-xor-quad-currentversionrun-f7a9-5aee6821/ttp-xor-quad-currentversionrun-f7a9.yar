rule TTP_XOR_QUAD_CurrentVersionRun_f7a9 {
  strings:
    $key_f7a9 = { a4 c6 [2] 80 c8 [2] ab e4 [2] 85 c6 [2] 91 dd [2] 9e c7 [2] 80 da [2] 82 db [2] 99 dd [2] 85 da [2] 99 f5 }

  condition:
    any of them
}