rule TTP_XOR_MULT_DOSStub_ca63 {
  strings:
    $key_ca63 = { 9e 0b [2] ea 13 [2] ad 11 [2] ea 00 [2] a4 0c [2] a8 06 [2] bf 0d [2] a4 43 [2] 99 }

  condition:
    any of them
}