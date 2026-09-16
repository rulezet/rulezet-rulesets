rule TTP_XOR_MULT_DOSStub_2474 {
  strings:
    $key_2474 = { 70 1c [2] 04 04 [2] 43 06 [2] 04 17 [2] 4a 1b [2] 46 11 [2] 51 1a [2] 4a 54 [2] 77 }

  condition:
    any of them
}