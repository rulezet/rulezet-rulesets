rule TTP_XOR_MULT_DOSStub_1419 {
  strings:
    $key_1419 = { 40 71 [2] 34 69 [2] 73 6b [2] 34 7a [2] 7a 76 [2] 76 7c [2] 61 77 [2] 7a 39 [2] 47 }

  condition:
    any of them
}