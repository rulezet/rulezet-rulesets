rule TTP_XOR_MULT_DOSStub_cf5e {
  strings:
    $key_cf5e = { 9b 36 [2] ef 2e [2] a8 2c [2] ef 3d [2] a1 31 [2] ad 3b [2] ba 30 [2] a1 7e [2] 9c }

  condition:
    any of them
}