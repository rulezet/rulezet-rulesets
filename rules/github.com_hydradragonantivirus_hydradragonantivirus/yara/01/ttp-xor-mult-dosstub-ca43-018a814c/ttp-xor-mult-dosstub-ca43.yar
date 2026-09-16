rule TTP_XOR_MULT_DOSStub_ca43 {
  strings:
    $key_ca43 = { 9e 2b [2] ea 33 [2] ad 31 [2] ea 20 [2] a4 2c [2] a8 26 [2] bf 2d [2] a4 63 [2] 99 }

  condition:
    any of them
}