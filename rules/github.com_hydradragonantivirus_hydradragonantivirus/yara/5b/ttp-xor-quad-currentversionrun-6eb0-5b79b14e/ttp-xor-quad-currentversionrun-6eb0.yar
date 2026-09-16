rule TTP_XOR_QUAD_CurrentVersionRun_6eb0 {
  strings:
    $key_6eb0 = { 3d df [2] 19 d1 [2] 32 fd [2] 1c df [2] 08 c4 [2] 07 de [2] 19 c3 [2] 1b c2 [2] 00 c4 [2] 1c c3 [2] 00 ec }

  condition:
    any of them
}