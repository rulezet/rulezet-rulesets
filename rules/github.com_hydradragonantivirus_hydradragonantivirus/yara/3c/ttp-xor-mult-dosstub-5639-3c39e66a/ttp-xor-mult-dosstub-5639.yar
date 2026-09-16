rule TTP_XOR_MULT_DOSStub_5639 {
  strings:
    $key_5639 = { 02 51 [2] 76 49 [2] 31 4b [2] 76 5a [2] 38 56 [2] 34 5c [2] 23 57 [2] 38 19 [2] 05 }

  condition:
    any of them
}