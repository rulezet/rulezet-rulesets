rule TTP_XOR_QUAD_CurrentVersionRun_e5a9 {
  strings:
    $key_e5a9 = { b6 c6 [2] 92 c8 [2] b9 e4 [2] 97 c6 [2] 83 dd [2] 8c c7 [2] 92 da [2] 90 db [2] 8b dd [2] 97 da [2] 8b f5 }

  condition:
    any of them
}