rule TTP_XOR_MULT_DOSStub_7a47 {
  strings:
    $key_7a47 = { 2e 2f [2] 5a 37 [2] 1d 35 [2] 5a 24 [2] 14 28 [2] 18 22 [2] 0f 29 [2] 14 67 [2] 29 }

  condition:
    any of them
}