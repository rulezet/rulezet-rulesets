rule TTP_XOR_MULT_DOSStub_ca80 {
  strings:
    $key_ca80 = { 9e e8 [2] ea f0 [2] ad f2 [2] ea e3 [2] a4 ef [2] a8 e5 [2] bf ee [2] a4 a0 [2] 99 }

  condition:
    any of them
}