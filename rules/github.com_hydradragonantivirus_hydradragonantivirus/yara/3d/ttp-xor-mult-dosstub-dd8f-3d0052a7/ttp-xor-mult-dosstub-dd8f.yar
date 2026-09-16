rule TTP_XOR_MULT_DOSStub_dd8f {
  strings:
    $key_dd8f = { 89 e7 [2] fd ff [2] ba fd [2] fd ec [2] b3 e0 [2] bf ea [2] a8 e1 [2] b3 af [2] 8e }

  condition:
    any of them
}