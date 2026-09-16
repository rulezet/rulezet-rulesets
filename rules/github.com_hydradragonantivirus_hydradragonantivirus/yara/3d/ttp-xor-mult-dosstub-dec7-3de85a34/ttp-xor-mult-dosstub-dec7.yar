rule TTP_XOR_MULT_DOSStub_dec7 {
  strings:
    $key_dec7 = { 8a af [2] fe b7 [2] b9 b5 [2] fe a4 [2] b0 a8 [2] bc a2 [2] ab a9 [2] b0 e7 [2] 8d }

  condition:
    any of them
}