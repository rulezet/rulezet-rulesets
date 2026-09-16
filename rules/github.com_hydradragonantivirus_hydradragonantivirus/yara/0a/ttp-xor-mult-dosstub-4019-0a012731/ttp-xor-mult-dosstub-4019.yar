rule TTP_XOR_MULT_DOSStub_4019 {
  strings:
    $key_4019 = { 14 71 [2] 60 69 [2] 27 6b [2] 60 7a [2] 2e 76 [2] 22 7c [2] 35 77 [2] 2e 39 [2] 13 }

  condition:
    any of them
}