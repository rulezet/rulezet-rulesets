rule TTP_XOR_QUAD_CurrentVersionRun_f0a9 {
  strings:
    $key_f0a9 = { a3 c6 [2] 87 c8 [2] ac e4 [2] 82 c6 [2] 96 dd [2] 99 c7 [2] 87 da [2] 85 db [2] 9e dd [2] 82 da [2] 9e f5 }

  condition:
    any of them
}