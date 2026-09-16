rule TTP_XOR_MULT_DOSStub_7614 {
  strings:
    $key_7614 = { 22 7c [2] 56 64 [2] 11 66 [2] 56 77 [2] 18 7b [2] 14 71 [2] 03 7a [2] 18 34 [2] 25 }

  condition:
    any of them
}