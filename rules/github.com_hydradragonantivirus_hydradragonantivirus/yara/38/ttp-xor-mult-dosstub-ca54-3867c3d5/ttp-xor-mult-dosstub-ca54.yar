rule TTP_XOR_MULT_DOSStub_ca54 {
  strings:
    $key_ca54 = { 9e 3c [2] ea 24 [2] ad 26 [2] ea 37 [2] a4 3b [2] a8 31 [2] bf 3a [2] a4 74 [2] 99 }

  condition:
    any of them
}