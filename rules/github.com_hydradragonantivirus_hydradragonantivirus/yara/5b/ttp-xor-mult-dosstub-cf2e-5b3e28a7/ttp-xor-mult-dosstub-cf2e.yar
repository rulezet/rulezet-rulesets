rule TTP_XOR_MULT_DOSStub_cf2e {
  strings:
    $key_cf2e = { 9b 46 [2] ef 5e [2] a8 5c [2] ef 4d [2] a1 41 [2] ad 4b [2] ba 40 [2] a1 0e [2] 9c }

  condition:
    any of them
}