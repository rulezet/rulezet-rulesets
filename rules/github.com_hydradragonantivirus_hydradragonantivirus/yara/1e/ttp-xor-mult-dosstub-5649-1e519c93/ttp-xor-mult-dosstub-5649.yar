rule TTP_XOR_MULT_DOSStub_5649 {
  strings:
    $key_5649 = { 02 21 [2] 76 39 [2] 31 3b [2] 76 2a [2] 38 26 [2] 34 2c [2] 23 27 [2] 38 69 [2] 05 }

  condition:
    any of them
}