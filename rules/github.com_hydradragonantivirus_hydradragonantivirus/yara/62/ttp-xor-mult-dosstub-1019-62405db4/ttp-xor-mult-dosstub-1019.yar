rule TTP_XOR_MULT_DOSStub_1019 {
  strings:
    $key_1019 = { 44 71 [2] 30 69 [2] 77 6b [2] 30 7a [2] 7e 76 [2] 72 7c [2] 65 77 [2] 7e 39 [2] 43 }

  condition:
    any of them
}