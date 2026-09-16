rule TTP_XOR_MULT_DOSStub_c9c3 {
  strings:
    $key_c9c3 = { 9d ab [2] e9 b3 [2] ae b1 [2] e9 a0 [2] a7 ac [2] ab a6 [2] bc ad [2] a7 e3 [2] 9a }

  condition:
    any of them
}