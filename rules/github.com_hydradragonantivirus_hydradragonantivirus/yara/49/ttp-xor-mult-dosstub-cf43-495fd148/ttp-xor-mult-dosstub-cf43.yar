rule TTP_XOR_MULT_DOSStub_cf43 {
  strings:
    $key_cf43 = { 9b 2b [2] ef 33 [2] a8 31 [2] ef 20 [2] a1 2c [2] ad 26 [2] ba 2d [2] a1 63 [2] 9c }

  condition:
    any of them
}