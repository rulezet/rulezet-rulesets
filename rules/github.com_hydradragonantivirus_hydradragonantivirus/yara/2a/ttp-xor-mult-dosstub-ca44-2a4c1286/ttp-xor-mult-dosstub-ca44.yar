rule TTP_XOR_MULT_DOSStub_ca44 {
  strings:
    $key_ca44 = { 9e 2c [2] ea 34 [2] ad 36 [2] ea 27 [2] a4 2b [2] a8 21 [2] bf 2a [2] a4 64 [2] 99 }

  condition:
    any of them
}