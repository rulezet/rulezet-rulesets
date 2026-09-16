rule TTP_XOR_QUAD_CurrentVersionRun_65a8 {
  strings:
    $key_65a8 = { 36 c7 [2] 12 c9 [2] 39 e5 [2] 17 c7 [2] 03 dc [2] 0c c6 [2] 12 db [2] 10 da [2] 0b dc [2] 17 db [2] 0b f4 }

  condition:
    any of them
}