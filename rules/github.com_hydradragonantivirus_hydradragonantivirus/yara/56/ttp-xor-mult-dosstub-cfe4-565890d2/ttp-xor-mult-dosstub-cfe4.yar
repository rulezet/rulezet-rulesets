rule TTP_XOR_MULT_DOSStub_cfe4 {
  strings:
    $key_cfe4 = { 9b 8c [2] ef 94 [2] a8 96 [2] ef 87 [2] a1 8b [2] ad 81 [2] ba 8a [2] a1 c4 [2] 9c }

  condition:
    any of them
}