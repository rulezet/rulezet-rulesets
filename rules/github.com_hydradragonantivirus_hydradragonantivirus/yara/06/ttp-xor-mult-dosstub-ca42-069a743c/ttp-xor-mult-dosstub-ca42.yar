rule TTP_XOR_MULT_DOSStub_ca42 {
  strings:
    $key_ca42 = { 9e 2a [2] ea 32 [2] ad 30 [2] ea 21 [2] a4 2d [2] a8 27 [2] bf 2c [2] a4 62 [2] 99 }

  condition:
    any of them
}