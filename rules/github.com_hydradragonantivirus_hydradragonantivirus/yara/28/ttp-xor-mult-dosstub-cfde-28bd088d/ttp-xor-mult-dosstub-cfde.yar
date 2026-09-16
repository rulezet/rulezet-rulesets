rule TTP_XOR_MULT_DOSStub_cfde {
  strings:
    $key_cfde = { 9b b6 [2] ef ae [2] a8 ac [2] ef bd [2] a1 b1 [2] ad bb [2] ba b0 [2] a1 fe [2] 9c }

  condition:
    any of them
}