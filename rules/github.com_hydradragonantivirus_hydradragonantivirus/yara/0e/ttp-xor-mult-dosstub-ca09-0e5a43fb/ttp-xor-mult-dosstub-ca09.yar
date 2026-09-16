rule TTP_XOR_MULT_DOSStub_ca09 {
  strings:
    $key_ca09 = { 9e 61 [2] ea 79 [2] ad 7b [2] ea 6a [2] a4 66 [2] a8 6c [2] bf 67 [2] a4 29 [2] 99 }

  condition:
    any of them
}