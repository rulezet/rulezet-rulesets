rule TTP_XOR_MULT_DOSStub_4517 {
  strings:
    $key_4517 = { 11 7f [2] 65 67 [2] 22 65 [2] 65 74 [2] 2b 78 [2] 27 72 [2] 30 79 [2] 2b 37 [2] 16 }

  condition:
    any of them
}