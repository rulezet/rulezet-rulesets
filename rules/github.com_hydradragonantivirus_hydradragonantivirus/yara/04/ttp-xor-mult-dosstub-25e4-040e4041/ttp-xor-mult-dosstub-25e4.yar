rule TTP_XOR_MULT_DOSStub_25e4 {
  strings:
    $key_25e4 = { 71 8c [2] 05 94 [2] 42 96 [2] 05 87 [2] 4b 8b [2] 47 81 [2] 50 8a [2] 4b c4 [2] 76 }

  condition:
    any of them
}