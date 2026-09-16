rule TTP_XOR_MULT_DOSStub_7647 {
  strings:
    $key_7647 = { 22 2f [2] 56 37 [2] 11 35 [2] 56 24 [2] 18 28 [2] 14 22 [2] 03 29 [2] 18 67 [2] 25 }

  condition:
    any of them
}