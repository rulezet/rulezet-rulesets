rule TTP_XOR_MULT_DOSStub_cf64 {
  strings:
    $key_cf64 = { 9b 0c [2] ef 14 [2] a8 16 [2] ef 07 [2] a1 0b [2] ad 01 [2] ba 0a [2] a1 44 [2] 9c }

  condition:
    any of them
}