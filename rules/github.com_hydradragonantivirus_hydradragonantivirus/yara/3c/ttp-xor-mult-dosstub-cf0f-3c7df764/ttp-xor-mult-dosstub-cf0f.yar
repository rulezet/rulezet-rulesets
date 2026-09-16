rule TTP_XOR_MULT_DOSStub_cf0f {
  strings:
    $key_cf0f = { 9b 67 [2] ef 7f [2] a8 7d [2] ef 6c [2] a1 60 [2] ad 6a [2] ba 61 [2] a1 2f [2] 9c }

  condition:
    any of them
}