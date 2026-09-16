rule TTP_XOR_MULT_DOSStub_1406 {
  strings:
    $key_1406 = { 40 6e [2] 34 76 [2] 73 74 [2] 34 65 [2] 7a 69 [2] 76 63 [2] 61 68 [2] 7a 26 [2] 47 }

  condition:
    any of them
}