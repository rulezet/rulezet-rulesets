rule TTP_XOR_MULT_DOSStub_cf00 {
  strings:
    $key_cf00 = { 9b 68 [2] ef 70 [2] a8 72 [2] ef 63 [2] a1 6f [2] ad 65 [2] ba 6e [2] a1 20 [2] 9c }

  condition:
    any of them
}