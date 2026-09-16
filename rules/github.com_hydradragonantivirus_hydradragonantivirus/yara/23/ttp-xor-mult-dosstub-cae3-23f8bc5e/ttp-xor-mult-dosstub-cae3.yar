rule TTP_XOR_MULT_DOSStub_cae3 {
  strings:
    $key_cae3 = { 9e 8b [2] ea 93 [2] ad 91 [2] ea 80 [2] a4 8c [2] a8 86 [2] bf 8d [2] a4 c3 [2] 99 }

  condition:
    any of them
}