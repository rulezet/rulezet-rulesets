rule TTP_XOR_MULT_DOSStub_ca56 {
  strings:
    $key_ca56 = { 9e 3e [2] ea 26 [2] ad 24 [2] ea 35 [2] a4 39 [2] a8 33 [2] bf 38 [2] a4 76 [2] 99 }

  condition:
    any of them
}