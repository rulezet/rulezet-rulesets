rule TTP_XOR_MULT_DOSStub_1075 {
  strings:
    $key_1075 = { 44 1d [2] 30 05 [2] 77 07 [2] 30 16 [2] 7e 1a [2] 72 10 [2] 65 1b [2] 7e 55 [2] 43 }

  condition:
    any of them
}