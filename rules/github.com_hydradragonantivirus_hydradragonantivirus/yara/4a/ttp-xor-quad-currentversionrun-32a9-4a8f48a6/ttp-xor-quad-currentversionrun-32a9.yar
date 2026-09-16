rule TTP_XOR_QUAD_CurrentVersionRun_32a9 {
  strings:
    $key_32a9 = { 61 c6 [2] 45 c8 [2] 6e e4 [2] 40 c6 [2] 54 dd [2] 5b c7 [2] 45 da [2] 47 db [2] 5c dd [2] 40 da [2] 5c f5 }

  condition:
    any of them
}