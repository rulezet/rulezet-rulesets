rule TTP_XOR_MULT_DOSStub_4547 {
  strings:
    $key_4547 = { 11 2f [2] 65 37 [2] 22 35 [2] 65 24 [2] 2b 28 [2] 27 22 [2] 30 29 [2] 2b 67 [2] 16 }

  condition:
    any of them
}