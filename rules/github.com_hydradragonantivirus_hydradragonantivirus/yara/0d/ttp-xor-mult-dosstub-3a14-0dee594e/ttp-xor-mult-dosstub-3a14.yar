rule TTP_XOR_MULT_DOSStub_3a14 {
  strings:
    $key_3a14 = { 6e 7c [2] 1a 64 [2] 5d 66 [2] 1a 77 [2] 54 7b [2] 58 71 [2] 4f 7a [2] 54 34 [2] 69 }

  condition:
    any of them
}