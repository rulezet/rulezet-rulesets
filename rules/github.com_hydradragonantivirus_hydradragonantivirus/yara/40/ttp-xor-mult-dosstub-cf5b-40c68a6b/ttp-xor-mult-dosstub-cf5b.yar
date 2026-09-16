rule TTP_XOR_MULT_DOSStub_cf5b {
  strings:
    $key_cf5b = { 9b 33 [2] ef 2b [2] a8 29 [2] ef 38 [2] a1 34 [2] ad 3e [2] ba 35 [2] a1 7b [2] 9c }

  condition:
    any of them
}