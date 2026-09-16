rule TTP_XOR_MULT_DOSStub_cf4b {
  strings:
    $key_cf4b = { 9b 23 [2] ef 3b [2] a8 39 [2] ef 28 [2] a1 24 [2] ad 2e [2] ba 25 [2] a1 6b [2] 9c }

  condition:
    any of them
}