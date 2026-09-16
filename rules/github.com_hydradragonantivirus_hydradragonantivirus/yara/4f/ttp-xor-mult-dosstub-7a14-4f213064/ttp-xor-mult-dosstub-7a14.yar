rule TTP_XOR_MULT_DOSStub_7a14 {
  strings:
    $key_7a14 = { 2e 7c [2] 5a 64 [2] 1d 66 [2] 5a 77 [2] 14 7b [2] 18 71 [2] 0f 7a [2] 14 34 [2] 29 }

  condition:
    any of them
}