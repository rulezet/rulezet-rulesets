rule TTP_XOR_MULT_DOSStub_ca15 {
  strings:
    $key_ca15 = { 9e 7d [2] ea 65 [2] ad 67 [2] ea 76 [2] a4 7a [2] a8 70 [2] bf 7b [2] a4 35 [2] 99 }

  condition:
    any of them
}