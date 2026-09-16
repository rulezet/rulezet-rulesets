rule TTP_XOR_MULT_DOSStub_1539 {
  strings:
    $key_1539 = { 41 51 [2] 35 49 [2] 72 4b [2] 35 5a [2] 7b 56 [2] 77 5c [2] 60 57 [2] 7b 19 [2] 46 }

  condition:
    any of them
}