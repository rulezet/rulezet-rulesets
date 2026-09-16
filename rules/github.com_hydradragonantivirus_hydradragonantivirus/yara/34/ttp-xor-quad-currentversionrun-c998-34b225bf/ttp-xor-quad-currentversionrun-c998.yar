rule TTP_XOR_QUAD_CurrentVersionRun_c998 {
  strings:
    $key_c998 = { 9a f7 [2] be f9 [2] 95 d5 [2] bb f7 [2] af ec [2] a0 f6 [2] be eb [2] bc ea [2] a7 ec [2] bb eb [2] a7 c4 }

  condition:
    any of them
}