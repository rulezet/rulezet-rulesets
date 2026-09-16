rule TTP_XOR_QUAD_CurrentVersionRun_f9a9 {
  strings:
    $key_f9a9 = { aa c6 [2] 8e c8 [2] a5 e4 [2] 8b c6 [2] 9f dd [2] 90 c7 [2] 8e da [2] 8c db [2] 97 dd [2] 8b da [2] 97 f5 }

  condition:
    any of them
}