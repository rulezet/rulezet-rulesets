rule TTP_XOR_QUAD_CurrentVersionRun_da8b {
  strings:
    $key_da8b = { 89 e4 [2] ad ea [2] 86 c6 [2] a8 e4 [2] bc ff [2] b3 e5 [2] ad f8 [2] af f9 [2] b4 ff [2] a8 f8 [2] b4 d7 }

  condition:
    any of them
}