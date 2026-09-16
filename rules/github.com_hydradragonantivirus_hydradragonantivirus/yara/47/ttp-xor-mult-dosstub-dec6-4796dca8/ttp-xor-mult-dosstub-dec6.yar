rule TTP_XOR_MULT_DOSStub_dec6 {
  strings:
    $key_dec6 = { 8a ae [2] fe b6 [2] b9 b4 [2] fe a5 [2] b0 a9 [2] bc a3 [2] ab a8 [2] b0 e6 [2] 8d }

  condition:
    any of them
}