rule TTP_XOR_MULT_DOSStub_3449 {
  strings:
    $key_3449 = { 60 21 [2] 14 39 [2] 53 3b [2] 14 2a [2] 5a 26 [2] 56 2c [2] 41 27 [2] 5a 69 [2] 67 }

  condition:
    any of them
}