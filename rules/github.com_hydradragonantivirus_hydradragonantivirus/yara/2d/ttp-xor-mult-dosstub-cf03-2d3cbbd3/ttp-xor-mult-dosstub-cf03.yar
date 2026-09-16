rule TTP_XOR_MULT_DOSStub_cf03 {
  strings:
    $key_cf03 = { 9b 6b [2] ef 73 [2] a8 71 [2] ef 60 [2] a1 6c [2] ad 66 [2] ba 6d [2] a1 23 [2] 9c }

  condition:
    any of them
}