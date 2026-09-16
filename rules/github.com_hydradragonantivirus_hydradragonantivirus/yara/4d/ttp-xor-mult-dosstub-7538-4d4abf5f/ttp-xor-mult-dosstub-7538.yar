rule TTP_XOR_MULT_DOSStub_7538 {
  strings:
    $key_7538 = { 21 50 [2] 55 48 [2] 12 4a [2] 55 5b [2] 1b 57 [2] 17 5d [2] 00 56 [2] 1b 18 [2] 26 }

  condition:
    any of them
}