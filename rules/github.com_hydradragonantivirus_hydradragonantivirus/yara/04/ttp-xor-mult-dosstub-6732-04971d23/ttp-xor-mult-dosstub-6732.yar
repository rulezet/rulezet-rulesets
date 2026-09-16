rule TTP_XOR_MULT_DOSStub_6732 {
  strings:
    $key_6732 = { 33 5a [2] 47 42 [2] 00 40 [2] 47 51 [2] 09 5d [2] 05 57 [2] 12 5c [2] 09 12 [2] 34 }

  condition:
    any of them
}