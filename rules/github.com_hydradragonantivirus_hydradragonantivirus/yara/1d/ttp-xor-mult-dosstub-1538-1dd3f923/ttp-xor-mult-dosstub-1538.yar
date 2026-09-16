rule TTP_XOR_MULT_DOSStub_1538 {
  strings:
    $key_1538 = { 41 50 [2] 35 48 [2] 72 4a [2] 35 5b [2] 7b 57 [2] 77 5d [2] 60 56 [2] 7b 18 [2] 46 }

  condition:
    any of them
}