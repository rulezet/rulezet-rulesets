rule TTP_XOR_MULT_DOSStub_cff4 {
  strings:
    $key_cff4 = { 9b 9c [2] ef 84 [2] a8 86 [2] ef 97 [2] a1 9b [2] ad 91 [2] ba 9a [2] a1 d4 [2] 9c }

  condition:
    any of them
}