rule TTP_XOR_MULT_DOSStub_ca76 {
  strings:
    $key_ca76 = { 9e 1e [2] ea 06 [2] ad 04 [2] ea 15 [2] a4 19 [2] a8 13 [2] bf 18 [2] a4 56 [2] 99 }

  condition:
    any of them
}