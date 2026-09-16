rule TTP_XOR_MULT_DOSStub_5656 {
  strings:
    $key_5656 = { 02 3e [2] 76 26 [2] 31 24 [2] 76 35 [2] 38 39 [2] 34 33 [2] 23 38 [2] 38 76 [2] 05 }

  condition:
    any of them
}