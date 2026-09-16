rule TTP_XOR_MULT_DOSStub_04e4 {
  strings:
    $key_04e4 = { 50 8c [2] 24 94 [2] 63 96 [2] 24 87 [2] 6a 8b [2] 66 81 [2] 71 8a [2] 6a c4 [2] 57 }

  condition:
    any of them
}