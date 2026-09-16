rule TTP_XOR_MULT_DOSStub_cf68 {
  strings:
    $key_cf68 = { 9b 00 [2] ef 18 [2] a8 1a [2] ef 0b [2] a1 07 [2] ad 0d [2] ba 06 [2] a1 48 [2] 9c }

  condition:
    any of them
}