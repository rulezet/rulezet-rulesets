rule TTP_XOR_MULT_DOSStub_1457 {
  strings:
    $key_1457 = { 40 3f [2] 34 27 [2] 73 25 [2] 34 34 [2] 7a 38 [2] 76 32 [2] 61 39 [2] 7a 77 [2] 47 }

  condition:
    any of them
}