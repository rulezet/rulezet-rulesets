rule TTP_XOR_MULT_DOSStub_c9c0 {
  strings:
    $key_c9c0 = { 9d a8 [2] e9 b0 [2] ae b2 [2] e9 a3 [2] a7 af [2] ab a5 [2] bc ae [2] a7 e0 [2] 9a }

  condition:
    any of them
}