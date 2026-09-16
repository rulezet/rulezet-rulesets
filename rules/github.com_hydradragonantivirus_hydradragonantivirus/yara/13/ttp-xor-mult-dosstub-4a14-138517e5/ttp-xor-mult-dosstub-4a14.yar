rule TTP_XOR_MULT_DOSStub_4a14 {
  strings:
    $key_4a14 = { 1e 7c [2] 6a 64 [2] 2d 66 [2] 6a 77 [2] 24 7b [2] 28 71 [2] 3f 7a [2] 24 34 [2] 19 }

  condition:
    any of them
}