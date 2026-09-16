rule TTP_XOR_MULT_DOSStub_0314 {
  strings:
    $key_0314 = { 57 7c [2] 23 64 [2] 64 66 [2] 23 77 [2] 6d 7b [2] 61 71 [2] 76 7a [2] 6d 34 [2] 50 }

  condition:
    any of them
}