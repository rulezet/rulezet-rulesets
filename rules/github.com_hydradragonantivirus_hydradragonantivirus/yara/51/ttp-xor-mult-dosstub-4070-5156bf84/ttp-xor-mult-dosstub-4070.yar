rule TTP_XOR_MULT_DOSStub_4070 {
  strings:
    $key_4070 = { 14 18 [2] 60 00 [2] 27 02 [2] 60 13 [2] 2e 1f [2] 22 15 [2] 35 1e [2] 2e 50 [2] 13 }

  condition:
    any of them
}