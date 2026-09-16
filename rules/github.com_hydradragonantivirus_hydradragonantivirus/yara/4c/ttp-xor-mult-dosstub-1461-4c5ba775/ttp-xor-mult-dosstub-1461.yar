rule TTP_XOR_MULT_DOSStub_1461 {
  strings:
    $key_1461 = { 40 09 [2] 34 11 [2] 73 13 [2] 34 02 [2] 7a 0e [2] 76 04 [2] 61 0f [2] 7a 41 [2] 47 }

  condition:
    any of them
}