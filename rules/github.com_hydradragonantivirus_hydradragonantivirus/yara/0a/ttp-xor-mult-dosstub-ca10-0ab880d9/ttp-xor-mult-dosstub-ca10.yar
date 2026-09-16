rule TTP_XOR_MULT_DOSStub_ca10 {
  strings:
    $key_ca10 = { 9e 78 [2] ea 60 [2] ad 62 [2] ea 73 [2] a4 7f [2] a8 75 [2] bf 7e [2] a4 30 [2] 99 }

  condition:
    any of them
}