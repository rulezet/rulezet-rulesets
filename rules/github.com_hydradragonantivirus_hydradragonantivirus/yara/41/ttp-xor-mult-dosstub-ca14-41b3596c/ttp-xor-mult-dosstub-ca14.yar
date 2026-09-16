rule TTP_XOR_MULT_DOSStub_ca14 {
  strings:
    $key_ca14 = { 9e 7c [2] ea 64 [2] ad 66 [2] ea 77 [2] a4 7b [2] a8 71 [2] bf 7a [2] a4 34 [2] 99 }

  condition:
    any of them
}