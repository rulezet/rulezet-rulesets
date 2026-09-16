rule TTP_XOR_MULT_DOSStub_1574 {
  strings:
    $key_1574 = { 41 1c [2] 35 04 [2] 72 06 [2] 35 17 [2] 7b 1b [2] 77 11 [2] 60 1a [2] 7b 54 [2] 46 }

  condition:
    any of them
}