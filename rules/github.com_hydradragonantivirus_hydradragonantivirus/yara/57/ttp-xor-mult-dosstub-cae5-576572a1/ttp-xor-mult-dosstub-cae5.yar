rule TTP_XOR_MULT_DOSStub_cae5 {
  strings:
    $key_cae5 = { 9e 8d [2] ea 95 [2] ad 97 [2] ea 86 [2] a4 8a [2] a8 80 [2] bf 8b [2] a4 c5 [2] 99 }

  condition:
    any of them
}