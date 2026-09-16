rule TTP_XOR_MULT_DOSStub_5640 {
  strings:
    $key_5640 = { 02 28 [2] 76 30 [2] 31 32 [2] 76 23 [2] 38 2f [2] 34 25 [2] 23 2e [2] 38 60 [2] 05 }

  condition:
    any of them
}