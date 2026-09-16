rule TTP_XOR_MULT_DOSStub_ca62 {
  strings:
    $key_ca62 = { 9e 0a [2] ea 12 [2] ad 10 [2] ea 01 [2] a4 0d [2] a8 07 [2] bf 0c [2] a4 42 [2] 99 }

  condition:
    any of them
}