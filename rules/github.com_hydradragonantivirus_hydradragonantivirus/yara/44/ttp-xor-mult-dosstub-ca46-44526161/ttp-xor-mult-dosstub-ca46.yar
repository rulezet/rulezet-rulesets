rule TTP_XOR_MULT_DOSStub_ca46 {
  strings:
    $key_ca46 = { 9e 2e [2] ea 36 [2] ad 34 [2] ea 25 [2] a4 29 [2] a8 23 [2] bf 28 [2] a4 66 [2] 99 }

  condition:
    any of them
}