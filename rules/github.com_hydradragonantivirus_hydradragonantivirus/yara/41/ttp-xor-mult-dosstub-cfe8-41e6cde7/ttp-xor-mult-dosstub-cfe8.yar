rule TTP_XOR_MULT_DOSStub_cfe8 {
  strings:
    $key_cfe8 = { 9b 80 [2] ef 98 [2] a8 9a [2] ef 8b [2] a1 87 [2] ad 8d [2] ba 86 [2] a1 c8 [2] 9c }

  condition:
    any of them
}