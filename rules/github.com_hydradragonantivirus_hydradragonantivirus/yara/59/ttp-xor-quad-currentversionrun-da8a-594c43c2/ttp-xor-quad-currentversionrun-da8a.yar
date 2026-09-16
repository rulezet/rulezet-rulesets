rule TTP_XOR_QUAD_CurrentVersionRun_da8a {
  strings:
    $key_da8a = { 89 e5 [2] ad eb [2] 86 c7 [2] a8 e5 [2] bc fe [2] b3 e4 [2] ad f9 [2] af f8 [2] b4 fe [2] a8 f9 [2] b4 d6 }

  condition:
    any of them
}