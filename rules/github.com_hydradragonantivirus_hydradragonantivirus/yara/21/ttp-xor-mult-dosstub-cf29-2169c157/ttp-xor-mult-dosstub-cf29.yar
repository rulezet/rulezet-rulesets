rule TTP_XOR_MULT_DOSStub_cf29 {
  strings:
    $key_cf29 = { 9b 41 [2] ef 59 [2] a8 5b [2] ef 4a [2] a1 46 [2] ad 4c [2] ba 47 [2] a1 09 [2] 9c }

  condition:
    any of them
}