rule TTP_XOR_MULT_DOSStub_ca17 {
  strings:
    $key_ca17 = { 9e 7f [2] ea 67 [2] ad 65 [2] ea 74 [2] a4 78 [2] a8 72 [2] bf 79 [2] a4 37 [2] 99 }

  condition:
    any of them
}