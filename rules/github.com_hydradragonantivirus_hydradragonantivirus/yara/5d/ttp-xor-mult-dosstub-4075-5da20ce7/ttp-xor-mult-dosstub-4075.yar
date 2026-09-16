rule TTP_XOR_MULT_DOSStub_4075 {
  strings:
    $key_4075 = { 14 1d [2] 60 05 [2] 27 07 [2] 60 16 [2] 2e 1a [2] 22 10 [2] 35 1b [2] 2e 55 [2] 13 }

  condition:
    any of them
}