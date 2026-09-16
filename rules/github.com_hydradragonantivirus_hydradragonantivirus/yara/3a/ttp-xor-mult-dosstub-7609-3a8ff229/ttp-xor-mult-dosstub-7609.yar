rule TTP_XOR_MULT_DOSStub_7609 {
  strings:
    $key_7609 = { 22 61 [2] 56 79 [2] 11 7b [2] 56 6a [2] 18 66 [2] 14 6c [2] 03 67 [2] 18 29 [2] 25 }

  condition:
    any of them
}