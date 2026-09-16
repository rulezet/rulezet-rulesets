rule TTP_XOR_MULT_DOSStub_cf06 {
  strings:
    $key_cf06 = { 9b 6e [2] ef 76 [2] a8 74 [2] ef 65 [2] a1 69 [2] ad 63 [2] ba 68 [2] a1 26 [2] 9c }

  condition:
    any of them
}