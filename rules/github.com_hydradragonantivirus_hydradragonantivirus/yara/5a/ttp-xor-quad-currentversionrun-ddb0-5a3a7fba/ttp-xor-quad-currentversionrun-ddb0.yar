rule TTP_XOR_QUAD_CurrentVersionRun_ddb0 {
  strings:
    $key_ddb0 = { 8e df [2] aa d1 [2] 81 fd [2] af df [2] bb c4 [2] b4 de [2] aa c3 [2] a8 c2 [2] b3 c4 [2] af c3 [2] b3 ec }

  condition:
    any of them
}