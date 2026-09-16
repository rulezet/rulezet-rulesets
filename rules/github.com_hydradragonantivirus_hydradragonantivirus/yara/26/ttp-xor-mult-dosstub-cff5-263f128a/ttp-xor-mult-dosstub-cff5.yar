rule TTP_XOR_MULT_DOSStub_cff5 {
  strings:
    $key_cff5 = { 9b 9d [2] ef 85 [2] a8 87 [2] ef 96 [2] a1 9a [2] ad 90 [2] ba 9b [2] a1 d5 [2] 9c }

  condition:
    any of them
}