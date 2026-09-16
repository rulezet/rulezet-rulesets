rule TTP_XOR_QUAD_CurrentVersionRun_e2a9 {
  strings:
    $key_e2a9 = { b1 c6 [2] 95 c8 [2] be e4 [2] 90 c6 [2] 84 dd [2] 8b c7 [2] 95 da [2] 97 db [2] 8c dd [2] 90 da [2] 8c f5 }

  condition:
    any of them
}