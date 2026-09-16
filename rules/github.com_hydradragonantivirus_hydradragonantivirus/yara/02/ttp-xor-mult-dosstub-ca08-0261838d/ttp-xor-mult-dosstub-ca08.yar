rule TTP_XOR_MULT_DOSStub_ca08 {
  strings:
    $key_ca08 = { 9e 60 [2] ea 78 [2] ad 7a [2] ea 6b [2] a4 67 [2] a8 6d [2] bf 66 [2] a4 28 [2] 99 }

  condition:
    any of them
}