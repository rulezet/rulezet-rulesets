rule TTP_XOR_MULT_DOSStub_6075 {
  strings:
    $key_6075 = { 34 1d [2] 40 05 [2] 07 07 [2] 40 16 [2] 0e 1a [2] 02 10 [2] 15 1b [2] 0e 55 [2] 33 }

  condition:
    any of them
}