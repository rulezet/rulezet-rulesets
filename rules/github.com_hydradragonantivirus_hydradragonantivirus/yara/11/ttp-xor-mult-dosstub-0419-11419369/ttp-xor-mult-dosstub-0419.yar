rule TTP_XOR_MULT_DOSStub_0419 {
  strings:
    $key_0419 = { 50 71 [2] 24 69 [2] 63 6b [2] 24 7a [2] 6a 76 [2] 66 7c [2] 71 77 [2] 6a 39 [2] 57 }

  condition:
    any of them
}