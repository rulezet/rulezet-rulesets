rule TTP_XOR_MULT_DOSStub_1533 {
  strings:
    $key_1533 = { 41 5b [2] 35 43 [2] 72 41 [2] 35 50 [2] 7b 5c [2] 77 56 [2] 60 5d [2] 7b 13 [2] 46 }

  condition:
    any of them
}