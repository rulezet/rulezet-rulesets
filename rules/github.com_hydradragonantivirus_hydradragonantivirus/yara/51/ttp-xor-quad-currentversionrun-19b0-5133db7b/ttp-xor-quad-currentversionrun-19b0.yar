rule TTP_XOR_QUAD_CurrentVersionRun_19b0 {
  strings:
    $key_19b0 = { 4a df [2] 6e d1 [2] 45 fd [2] 6b df [2] 7f c4 [2] 70 de [2] 6e c3 [2] 6c c2 [2] 77 c4 [2] 6b c3 [2] 77 ec }

  condition:
    any of them
}