rule TTP_XOR_MULT_DOSStub_ca02 {
  strings:
    $key_ca02 = { 9e 6a [2] ea 72 [2] ad 70 [2] ea 61 [2] a4 6d [2] a8 67 [2] bf 6c [2] a4 22 [2] 99 }

  condition:
    any of them
}