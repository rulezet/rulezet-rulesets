rule TTP_XOR_MULT_DOSStub_ca50 {
  strings:
    $key_ca50 = { 9e 38 [2] ea 20 [2] ad 22 [2] ea 33 [2] a4 3f [2] a8 35 [2] bf 3e [2] a4 70 [2] 99 }

  condition:
    any of them
}