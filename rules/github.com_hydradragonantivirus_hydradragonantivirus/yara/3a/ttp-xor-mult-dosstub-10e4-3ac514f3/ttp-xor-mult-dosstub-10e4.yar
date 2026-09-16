rule TTP_XOR_MULT_DOSStub_10e4 {
  strings:
    $key_10e4 = { 44 8c [2] 30 94 [2] 77 96 [2] 30 87 [2] 7e 8b [2] 72 81 [2] 65 8a [2] 7e c4 [2] 43 }

  condition:
    any of them
}