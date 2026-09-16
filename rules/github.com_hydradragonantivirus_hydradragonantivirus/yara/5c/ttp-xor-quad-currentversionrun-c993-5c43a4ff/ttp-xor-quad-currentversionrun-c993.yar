rule TTP_XOR_QUAD_CurrentVersionRun_c993 {
  strings:
    $key_c993 = { 9a fc [2] be f2 [2] 95 de [2] bb fc [2] af e7 [2] a0 fd [2] be e0 [2] bc e1 [2] a7 e7 [2] bb e0 [2] a7 cf }

  condition:
    any of them
}