rule TTP_XOR_MULT_DOSStub_6740 {
  strings:
    $key_6740 = { 33 28 [2] 47 30 [2] 00 32 [2] 47 23 [2] 09 2f [2] 05 25 [2] 12 2e [2] 09 60 [2] 34 }

  condition:
    any of them
}