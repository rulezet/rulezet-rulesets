rule TTP_XOR_MULT_DOSStub_7a38 {
  strings:
    $key_7a38 = { 2e 50 [2] 5a 48 [2] 1d 4a [2] 5a 5b [2] 14 57 [2] 18 5d [2] 0f 56 [2] 14 18 [2] 29 }

  condition:
    any of them
}