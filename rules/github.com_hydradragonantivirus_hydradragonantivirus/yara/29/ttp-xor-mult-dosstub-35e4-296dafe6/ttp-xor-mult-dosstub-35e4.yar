rule TTP_XOR_MULT_DOSStub_35e4 {
  strings:
    $key_35e4 = { 61 8c [2] 15 94 [2] 52 96 [2] 15 87 [2] 5b 8b [2] 57 81 [2] 40 8a [2] 5b c4 [2] 66 }

  condition:
    any of them
}