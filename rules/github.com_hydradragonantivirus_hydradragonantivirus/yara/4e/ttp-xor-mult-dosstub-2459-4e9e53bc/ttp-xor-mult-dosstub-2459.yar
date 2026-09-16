rule TTP_XOR_MULT_DOSStub_2459 {
  strings:
    $key_2459 = { 70 31 [2] 04 29 [2] 43 2b [2] 04 3a [2] 4a 36 [2] 46 3c [2] 51 37 [2] 4a 79 [2] 77 }

  condition:
    any of them
}