rule TTP_XOR_QUAD_CurrentVersionRun_fcb0 {
  strings:
    $key_fcb0 = { af df [2] 8b d1 [2] a0 fd [2] 8e df [2] 9a c4 [2] 95 de [2] 8b c3 [2] 89 c2 [2] 92 c4 [2] 8e c3 [2] 92 ec }

  condition:
    any of them
}