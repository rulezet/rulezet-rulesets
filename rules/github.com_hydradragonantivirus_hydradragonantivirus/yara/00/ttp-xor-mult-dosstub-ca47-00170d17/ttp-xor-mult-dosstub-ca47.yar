rule TTP_XOR_MULT_DOSStub_ca47 {
  strings:
    $key_ca47 = { 9e 2f [2] ea 37 [2] ad 35 [2] ea 24 [2] a4 28 [2] a8 22 [2] bf 29 [2] a4 67 [2] 99 }

  condition:
    any of them
}