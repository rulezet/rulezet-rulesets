rule TTP_XOR_QUAD_CurrentVersionRun_f7a8 {
  strings:
    $key_f7a8 = { a4 c7 [2] 80 c9 [2] ab e5 [2] 85 c7 [2] 91 dc [2] 9e c6 [2] 80 db [2] 82 da [2] 99 dc [2] 85 db [2] 99 f4 }

  condition:
    any of them
}