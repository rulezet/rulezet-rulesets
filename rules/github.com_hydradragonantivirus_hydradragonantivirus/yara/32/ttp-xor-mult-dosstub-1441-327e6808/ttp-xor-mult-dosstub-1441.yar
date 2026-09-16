rule TTP_XOR_MULT_DOSStub_1441 {
  strings:
    $key_1441 = { 40 29 [2] 34 31 [2] 73 33 [2] 34 22 [2] 7a 2e [2] 76 24 [2] 61 2f [2] 7a 61 [2] 47 }

  condition:
    any of them
}