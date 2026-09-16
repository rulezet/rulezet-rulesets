rule TTP_XOR_QUAD_CurrentVersionRun_09b0 {
  strings:
    $key_09b0 = { 5a df [2] 7e d1 [2] 55 fd [2] 7b df [2] 6f c4 [2] 60 de [2] 7e c3 [2] 7c c2 [2] 67 c4 [2] 7b c3 [2] 67 ec }

  condition:
    any of them
}