rule TTP_XOR_MULT_DOSStub_5257 {
  strings:
    $key_5257 = { 06 3f [2] 72 27 [2] 35 25 [2] 72 34 [2] 3c 38 [2] 30 32 [2] 27 39 [2] 3c 77 [2] 01 }

  condition:
    any of them
}