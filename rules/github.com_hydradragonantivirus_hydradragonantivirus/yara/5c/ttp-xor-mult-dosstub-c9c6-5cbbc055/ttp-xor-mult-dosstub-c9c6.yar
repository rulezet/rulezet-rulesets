rule TTP_XOR_MULT_DOSStub_c9c6 {
  strings:
    $key_c9c6 = { 9d ae [2] e9 b6 [2] ae b4 [2] e9 a5 [2] a7 a9 [2] ab a3 [2] bc a8 [2] a7 e6 [2] 9a }

  condition:
    any of them
}