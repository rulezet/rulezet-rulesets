rule TTP_XOR_MULT_DOSStub_6739 {
  strings:
    $key_6739 = { 33 51 [2] 47 49 [2] 00 4b [2] 47 5a [2] 09 56 [2] 05 5c [2] 12 57 [2] 09 19 [2] 34 }

  condition:
    any of them
}