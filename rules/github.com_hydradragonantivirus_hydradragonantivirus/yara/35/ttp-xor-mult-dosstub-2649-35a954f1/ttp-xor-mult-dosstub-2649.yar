rule TTP_XOR_MULT_DOSStub_2649 {
  strings:
    $key_2649 = { 72 21 [2] 06 39 [2] 41 3b [2] 06 2a [2] 48 26 [2] 44 2c [2] 53 27 [2] 48 69 [2] 75 }

  condition:
    any of them
}