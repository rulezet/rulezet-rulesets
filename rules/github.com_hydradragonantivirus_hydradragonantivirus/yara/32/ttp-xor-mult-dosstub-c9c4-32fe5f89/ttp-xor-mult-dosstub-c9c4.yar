rule TTP_XOR_MULT_DOSStub_c9c4 {
  strings:
    $key_c9c4 = { 9d ac [2] e9 b4 [2] ae b6 [2] e9 a7 [2] a7 ab [2] ab a1 [2] bc aa [2] a7 e4 [2] 9a }

  condition:
    any of them
}