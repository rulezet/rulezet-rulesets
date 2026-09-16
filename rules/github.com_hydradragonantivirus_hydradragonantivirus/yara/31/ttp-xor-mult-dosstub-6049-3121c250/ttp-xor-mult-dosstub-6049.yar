rule TTP_XOR_MULT_DOSStub_6049 {
  strings:
    $key_6049 = { 34 21 [2] 40 39 [2] 07 3b [2] 40 2a [2] 0e 26 [2] 02 2c [2] 15 27 [2] 0e 69 [2] 33 }

  condition:
    any of them
}