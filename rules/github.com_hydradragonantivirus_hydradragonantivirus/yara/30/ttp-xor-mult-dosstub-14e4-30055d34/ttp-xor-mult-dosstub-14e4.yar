rule TTP_XOR_MULT_DOSStub_14e4 {
  strings:
    $key_14e4 = { 40 8c [2] 34 94 [2] 73 96 [2] 34 87 [2] 7a 8b [2] 76 81 [2] 61 8a [2] 7a c4 [2] 47 }

  condition:
    any of them
}