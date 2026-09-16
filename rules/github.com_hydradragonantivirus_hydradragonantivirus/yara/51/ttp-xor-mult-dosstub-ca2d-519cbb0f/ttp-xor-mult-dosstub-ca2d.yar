rule TTP_XOR_MULT_DOSStub_ca2d {
  strings:
    $key_ca2d = { 9e 45 [2] ea 5d [2] ad 5f [2] ea 4e [2] a4 42 [2] a8 48 [2] bf 43 [2] a4 0d [2] 99 }

  condition:
    any of them
}