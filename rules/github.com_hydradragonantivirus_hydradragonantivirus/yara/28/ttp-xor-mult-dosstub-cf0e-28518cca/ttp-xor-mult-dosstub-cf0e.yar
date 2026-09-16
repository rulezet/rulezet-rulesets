rule TTP_XOR_MULT_DOSStub_cf0e {
  strings:
    $key_cf0e = { 9b 66 [2] ef 7e [2] a8 7c [2] ef 6d [2] a1 61 [2] ad 6b [2] ba 60 [2] a1 2e [2] 9c }

  condition:
    any of them
}