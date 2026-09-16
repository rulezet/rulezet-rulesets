rule TTP_XOR_MULT_DOSStub_7a56 {
  strings:
    $key_7a56 = { 2e 3e [2] 5a 26 [2] 1d 24 [2] 5a 35 [2] 14 39 [2] 18 33 [2] 0f 38 [2] 14 76 [2] 29 }

  condition:
    any of them
}