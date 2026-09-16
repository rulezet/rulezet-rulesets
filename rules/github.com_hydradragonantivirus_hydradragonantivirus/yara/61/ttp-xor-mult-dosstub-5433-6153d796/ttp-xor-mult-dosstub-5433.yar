rule TTP_XOR_MULT_DOSStub_5433 {
  strings:
    $key_5433 = { 00 5b [2] 74 43 [2] 33 41 [2] 74 50 [2] 3a 5c [2] 36 56 [2] 21 5d [2] 3a 13 [2] 07 }

  condition:
    any of them
}