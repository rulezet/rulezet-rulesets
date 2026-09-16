rule TTP_XOR_MULT_DOSStub_4314 {
  strings:
    $key_4314 = { 17 7c [2] 63 64 [2] 24 66 [2] 63 77 [2] 2d 7b [2] 21 71 [2] 36 7a [2] 2d 34 [2] 10 }

  condition:
    any of them
}