rule TTP_XOR_MULT_DOSStub_7319 {
  strings:
    $key_7319 = { 27 71 [2] 53 69 [2] 14 6b [2] 53 7a [2] 1d 76 [2] 11 7c [2] 06 77 [2] 1d 39 [2] 20 }

  condition:
    any of them
}