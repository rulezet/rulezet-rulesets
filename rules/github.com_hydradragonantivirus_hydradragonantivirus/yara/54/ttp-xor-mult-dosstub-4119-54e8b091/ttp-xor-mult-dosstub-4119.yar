rule TTP_XOR_MULT_DOSStub_4119 {
  strings:
    $key_4119 = { 15 71 [2] 61 69 [2] 26 6b [2] 61 7a [2] 2f 76 [2] 23 7c [2] 34 77 [2] 2f 39 [2] 12 }

  condition:
    any of them
}