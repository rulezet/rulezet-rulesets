rule TTP_XOR_QUAD_CurrentVersionRun_0eb0 {
  strings:
    $key_0eb0 = { 5d df [2] 79 d1 [2] 52 fd [2] 7c df [2] 68 c4 [2] 67 de [2] 79 c3 [2] 7b c2 [2] 60 c4 [2] 7c c3 [2] 60 ec }

  condition:
    any of them
}