rule TTP_XOR_MULT_DOSStub_1525 {
  strings:
    $key_1525 = { 41 4d [2] 35 55 [2] 72 57 [2] 35 46 [2] 7b 4a [2] 77 40 [2] 60 4b [2] 7b 05 [2] 46 }

  condition:
    any of them
}