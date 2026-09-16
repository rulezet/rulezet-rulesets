rule TTP_XOR_MULT_DOSStub_ca31 {
  strings:
    $key_ca31 = { 9e 59 [2] ea 41 [2] ad 43 [2] ea 52 [2] a4 5e [2] a8 54 [2] bf 5f [2] a4 11 [2] 99 }

  condition:
    any of them
}