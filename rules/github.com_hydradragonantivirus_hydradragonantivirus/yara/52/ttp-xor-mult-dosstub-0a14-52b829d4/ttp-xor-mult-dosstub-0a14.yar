rule TTP_XOR_MULT_DOSStub_0a14 {
  strings:
    $key_0a14 = { 5e 7c [2] 2a 64 [2] 6d 66 [2] 2a 77 [2] 64 7b [2] 68 71 [2] 7f 7a [2] 64 34 [2] 59 }

  condition:
    any of them
}