rule TTP_XOR_MULT_DOSStub_cff3 {
  strings:
    $key_cff3 = { 9b 9b [2] ef 83 [2] a8 81 [2] ef 90 [2] a1 9c [2] ad 96 [2] ba 9d [2] a1 d3 [2] 9c }

  condition:
    any of them
}