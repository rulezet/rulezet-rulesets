rule TTP_XOR_MULT_DOSStub_cf32 {
  strings:
    $key_cf32 = { 9b 5a [2] ef 42 [2] a8 40 [2] ef 51 [2] a1 5d [2] ad 57 [2] ba 5c [2] a1 12 [2] 9c }

  condition:
    any of them
}