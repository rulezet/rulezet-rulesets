rule TTP_XOR_MULT_DOSStub_1447 {
  strings:
    $key_1447 = { 40 2f [2] 34 37 [2] 73 35 [2] 34 24 [2] 7a 28 [2] 76 22 [2] 61 29 [2] 7a 67 [2] 47 }

  condition:
    any of them
}