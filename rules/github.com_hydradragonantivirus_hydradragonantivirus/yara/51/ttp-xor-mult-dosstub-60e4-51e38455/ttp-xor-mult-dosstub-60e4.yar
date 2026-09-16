rule TTP_XOR_MULT_DOSStub_60e4 {
  strings:
    $key_60e4 = { 34 8c [2] 40 94 [2] 07 96 [2] 40 87 [2] 0e 8b [2] 02 81 [2] 15 8a [2] 0e c4 [2] 33 }

  condition:
    any of them
}