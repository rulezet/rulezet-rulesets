rule TTP_XOR_MULT_DOSStub_4614 {
  strings:
    $key_4614 = { 12 7c [2] 66 64 [2] 21 66 [2] 66 77 [2] 28 7b [2] 24 71 [2] 33 7a [2] 28 34 [2] 15 }

  condition:
    any of them
}