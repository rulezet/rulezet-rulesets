rule TTP_XOR_MULT_DOSStub_5456 {
  strings:
    $key_5456 = { 00 3e [2] 74 26 [2] 33 24 [2] 74 35 [2] 3a 39 [2] 36 33 [2] 21 38 [2] 3a 76 [2] 07 }

  condition:
    any of them
}