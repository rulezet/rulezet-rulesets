rule TTP_XOR_QUAD_CurrentVersionRun_55a9 {
  strings:
    $key_55a9 = { 06 c6 [2] 22 c8 [2] 09 e4 [2] 27 c6 [2] 33 dd [2] 3c c7 [2] 22 da [2] 20 db [2] 3b dd [2] 27 da [2] 3b f5 }

  condition:
    any of them
}