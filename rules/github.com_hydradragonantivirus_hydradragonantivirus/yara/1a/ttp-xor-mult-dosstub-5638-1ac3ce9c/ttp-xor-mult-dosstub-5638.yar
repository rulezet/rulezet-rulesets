rule TTP_XOR_MULT_DOSStub_5638 {
  strings:
    $key_5638 = { 02 50 [2] 76 48 [2] 31 4a [2] 76 5b [2] 38 57 [2] 34 5d [2] 23 56 [2] 38 18 [2] 05 }

  condition:
    any of them
}