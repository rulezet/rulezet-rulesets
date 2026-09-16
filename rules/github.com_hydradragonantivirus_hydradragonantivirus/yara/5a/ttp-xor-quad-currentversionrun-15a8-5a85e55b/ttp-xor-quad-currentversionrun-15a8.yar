rule TTP_XOR_QUAD_CurrentVersionRun_15a8 {
  strings:
    $key_15a8 = { 46 c7 [2] 62 c9 [2] 49 e5 [2] 67 c7 [2] 73 dc [2] 7c c6 [2] 62 db [2] 60 da [2] 7b dc [2] 67 db [2] 7b f4 }

  condition:
    any of them
}