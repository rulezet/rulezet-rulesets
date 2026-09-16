rule TTP_XOR_QUAD_CurrentVersionRun_da99 {
  strings:
    $key_da99 = { 89 f6 [2] ad f8 [2] 86 d4 [2] a8 f6 [2] bc ed [2] b3 f7 [2] ad ea [2] af eb [2] b4 ed [2] a8 ea [2] b4 c5 }

  condition:
    any of them
}