rule TTP_XOR_MULT_DOSStub_1463 {
  strings:
    $key_1463 = { 40 0b [2] 34 13 [2] 73 11 [2] 34 00 [2] 7a 0c [2] 76 06 [2] 61 0d [2] 7a 43 [2] 47 }

  condition:
    any of them
}