rule TTP_XOR_MULT_DOSStub_c9a6 {
  strings:
    $key_c9a6 = { 9d ce [2] e9 d6 [2] ae d4 [2] e9 c5 [2] a7 c9 [2] ab c3 [2] bc c8 [2] a7 86 [2] 9a }

  condition:
    any of them
}