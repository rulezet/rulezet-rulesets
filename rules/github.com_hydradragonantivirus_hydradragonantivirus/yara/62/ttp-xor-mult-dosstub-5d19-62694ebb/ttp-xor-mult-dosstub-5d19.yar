rule TTP_XOR_MULT_DOSStub_5d19 {
  strings:
    $key_5d19 = { 09 71 [2] 7d 69 [2] 3a 6b [2] 7d 7a [2] 33 76 [2] 3f 7c [2] 28 77 [2] 33 39 [2] 0e }

  condition:
    any of them
}