rule TTP_XOR_MULT_DOSStub_ca32 {
  strings:
    $key_ca32 = { 9e 5a [2] ea 42 [2] ad 40 [2] ea 51 [2] a4 5d [2] a8 57 [2] bf 5c [2] a4 12 [2] 99 }

  condition:
    any of them
}