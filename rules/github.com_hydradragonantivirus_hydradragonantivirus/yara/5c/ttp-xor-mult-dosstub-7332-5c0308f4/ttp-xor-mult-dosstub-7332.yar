rule TTP_XOR_MULT_DOSStub_7332 {
  strings:
    $key_7332 = { 27 5a [2] 53 42 [2] 14 40 [2] 53 51 [2] 1d 5d [2] 11 57 [2] 06 5c [2] 1d 12 [2] 20 }

  condition:
    any of them
}