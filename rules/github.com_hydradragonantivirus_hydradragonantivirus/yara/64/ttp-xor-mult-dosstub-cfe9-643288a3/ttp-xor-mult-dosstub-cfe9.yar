rule TTP_XOR_MULT_DOSStub_cfe9 {
  strings:
    $key_cfe9 = { 9b 81 [2] ef 99 [2] a8 9b [2] ef 8a [2] a1 86 [2] ad 8c [2] ba 87 [2] a1 c9 [2] 9c }

  condition:
    any of them
}