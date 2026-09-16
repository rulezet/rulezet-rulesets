rule TTP_XOR_MULT_DOSStub_cade {
  strings:
    $key_cade = { 9e b6 [2] ea ae [2] ad ac [2] ea bd [2] a4 b1 [2] a8 bb [2] bf b0 [2] a4 fe [2] 99 }

  condition:
    any of them
}