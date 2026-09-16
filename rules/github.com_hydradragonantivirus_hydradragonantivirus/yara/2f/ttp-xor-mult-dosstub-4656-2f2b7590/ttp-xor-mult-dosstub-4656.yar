rule TTP_XOR_MULT_DOSStub_4656 {
  strings:
    $key_4656 = { 12 3e [2] 66 26 [2] 21 24 [2] 66 35 [2] 28 39 [2] 24 33 [2] 33 38 [2] 28 76 [2] 15 }

  condition:
    any of them
}