rule TTP_XOR_MULT_DOSStub_4a19 {
  strings:
    $key_4a19 = { 1e 71 [2] 6a 69 [2] 2d 6b [2] 6a 7a [2] 24 76 [2] 28 7c [2] 3f 77 [2] 24 39 [2] 19 }

  condition:
    any of them
}