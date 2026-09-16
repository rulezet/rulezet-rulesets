rule TTP_XOR_MULT_DOSStub_ca86 {
  strings:
    $key_ca86 = { 9e ee [2] ea f6 [2] ad f4 [2] ea e5 [2] a4 e9 [2] a8 e3 [2] bf e8 [2] a4 a6 [2] 99 }

  condition:
    any of them
}