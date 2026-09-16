rule TTP_XOR_QUAD_CurrentVersionRun_2cb0 {
  strings:
    $key_2cb0 = { 7f df [2] 5b d1 [2] 70 fd [2] 5e df [2] 4a c4 [2] 45 de [2] 5b c3 [2] 59 c2 [2] 42 c4 [2] 5e c3 [2] 42 ec }

  condition:
    any of them
}