rule TTP_XOR_MULT_DOSStub_2574 {
  strings:
    $key_2574 = { 71 1c [2] 05 04 [2] 42 06 [2] 05 17 [2] 4b 1b [2] 47 11 [2] 50 1a [2] 4b 54 [2] 76 }

  condition:
    any of them
}