rule TTP_XOR_MULT_DOSStub_7a34 {
  strings:
    $key_7a34 = { 2e 5c [2] 5a 44 [2] 1d 46 [2] 5a 57 [2] 14 5b [2] 18 51 [2] 0f 5a [2] 14 14 [2] 29 }

  condition:
    any of them
}