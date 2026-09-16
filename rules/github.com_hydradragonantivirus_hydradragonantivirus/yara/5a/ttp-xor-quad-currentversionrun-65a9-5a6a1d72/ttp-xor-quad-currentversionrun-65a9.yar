rule TTP_XOR_QUAD_CurrentVersionRun_65a9 {
  strings:
    $key_65a9 = { 36 c6 [2] 12 c8 [2] 39 e4 [2] 17 c6 [2] 03 dd [2] 0c c7 [2] 12 da [2] 10 db [2] 0b dd [2] 17 da [2] 0b f5 }

  condition:
    any of them
}