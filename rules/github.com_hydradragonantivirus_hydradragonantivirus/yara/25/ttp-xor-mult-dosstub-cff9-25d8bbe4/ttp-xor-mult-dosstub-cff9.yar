rule TTP_XOR_MULT_DOSStub_cff9 {
  strings:
    $key_cff9 = { 9b 91 [2] ef 89 [2] a8 8b [2] ef 9a [2] a1 96 [2] ad 9c [2] ba 97 [2] a1 d9 [2] 9c }

  condition:
    any of them
}