rule TTP_XOR_QUAD_CurrentVersionRun_15a9 {
  strings:
    $key_15a9 = { 46 c6 [2] 62 c8 [2] 49 e4 [2] 67 c6 [2] 73 dd [2] 7c c7 [2] 62 da [2] 60 db [2] 7b dd [2] 67 da [2] 7b f5 }

  condition:
    any of them
}