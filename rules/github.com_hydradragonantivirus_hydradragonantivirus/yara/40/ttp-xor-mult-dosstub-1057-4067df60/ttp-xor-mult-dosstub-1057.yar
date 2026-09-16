rule TTP_XOR_MULT_DOSStub_1057 {
  strings:
    $key_1057 = { 44 3f [2] 30 27 [2] 77 25 [2] 30 34 [2] 7e 38 [2] 72 32 [2] 65 39 [2] 7e 77 [2] 43 }

  condition:
    any of them
}