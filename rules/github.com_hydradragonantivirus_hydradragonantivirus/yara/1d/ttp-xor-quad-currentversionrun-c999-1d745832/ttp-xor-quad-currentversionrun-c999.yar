rule TTP_XOR_QUAD_CurrentVersionRun_c999 {
  strings:
    $key_c999 = { 9a f6 [2] be f8 [2] 95 d4 [2] bb f6 [2] af ed [2] a0 f7 [2] be ea [2] bc eb [2] a7 ed [2] bb ea [2] a7 c5 }

  condition:
    any of them
}