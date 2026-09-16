rule TTP_XOR_MULT_DOSStub_4d19 {
  strings:
    $key_4d19 = { 19 71 [2] 6d 69 [2] 2a 6b [2] 6d 7a [2] 23 76 [2] 2f 7c [2] 38 77 [2] 23 39 [2] 1e }

  condition:
    any of them
}