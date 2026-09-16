rule TTP_XOR_MULT_DOSStub_7a04 {
  strings:
    $key_7a04 = { 2e 6c [2] 5a 74 [2] 1d 76 [2] 5a 67 [2] 14 6b [2] 18 61 [2] 0f 6a [2] 14 24 [2] 29 }

  condition:
    any of them
}