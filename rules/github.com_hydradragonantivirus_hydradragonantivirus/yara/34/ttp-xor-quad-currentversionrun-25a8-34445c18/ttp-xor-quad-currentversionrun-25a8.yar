rule TTP_XOR_QUAD_CurrentVersionRun_25a8 {
  strings:
    $key_25a8 = { 76 c7 [2] 52 c9 [2] 79 e5 [2] 57 c7 [2] 43 dc [2] 4c c6 [2] 52 db [2] 50 da [2] 4b dc [2] 57 db [2] 4b f4 }

  condition:
    any of them
}