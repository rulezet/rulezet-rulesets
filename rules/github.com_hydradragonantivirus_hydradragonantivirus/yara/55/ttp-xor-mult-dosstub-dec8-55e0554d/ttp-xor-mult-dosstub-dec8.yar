rule TTP_XOR_MULT_DOSStub_dec8 {
  strings:
    $key_dec8 = { 8a a0 [2] fe b8 [2] b9 ba [2] fe ab [2] b0 a7 [2] bc ad [2] ab a6 [2] b0 e8 [2] 8d }

  condition:
    any of them
}