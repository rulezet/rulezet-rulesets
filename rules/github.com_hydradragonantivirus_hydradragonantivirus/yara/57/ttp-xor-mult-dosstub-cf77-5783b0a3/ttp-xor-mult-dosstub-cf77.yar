rule TTP_XOR_MULT_DOSStub_cf77 {
  strings:
    $key_cf77 = { 9b 1f [2] ef 07 [2] a8 05 [2] ef 14 [2] a1 18 [2] ad 12 [2] ba 19 [2] a1 57 [2] 9c }

  condition:
    any of them
}