rule TTP_XOR_MULT_DOSStub_ca28 {
  strings:
    $key_ca28 = { 9e 40 [2] ea 58 [2] ad 5a [2] ea 4b [2] a4 47 [2] a8 4d [2] bf 46 [2] a4 08 [2] 99 }

  condition:
    any of them
}