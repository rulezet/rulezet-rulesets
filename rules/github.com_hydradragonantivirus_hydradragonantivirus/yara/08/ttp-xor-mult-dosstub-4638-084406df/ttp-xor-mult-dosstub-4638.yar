rule TTP_XOR_MULT_DOSStub_4638 {
  strings:
    $key_4638 = { 12 50 [2] 66 48 [2] 21 4a [2] 66 5b [2] 28 57 [2] 24 5d [2] 33 56 [2] 28 18 [2] 15 }

  condition:
    any of them
}