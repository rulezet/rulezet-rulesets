rule TTP_XOR_MULT_DOSStub_caa7 {
  strings:
    $key_caa7 = { 9e cf [2] ea d7 [2] ad d5 [2] ea c4 [2] a4 c8 [2] a8 c2 [2] bf c9 [2] a4 87 [2] 99 }

  condition:
    any of them
}