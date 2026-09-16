rule TTP_XOR_MULT_DOSStub_ca49 {
  strings:
    $key_ca49 = { 9e 21 [2] ea 39 [2] ad 3b [2] ea 2a [2] a4 26 [2] a8 2c [2] bf 27 [2] a4 69 [2] 99 }

  condition:
    any of them
}