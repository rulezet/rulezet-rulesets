rule TTP_XOR_QUAD_CurrentVersionRun_fdb0 {
  strings:
    $key_fdb0 = { ae df [2] 8a d1 [2] a1 fd [2] 8f df [2] 9b c4 [2] 94 de [2] 8a c3 [2] 88 c2 [2] 93 c4 [2] 8f c3 [2] 93 ec }

  condition:
    any of them
}