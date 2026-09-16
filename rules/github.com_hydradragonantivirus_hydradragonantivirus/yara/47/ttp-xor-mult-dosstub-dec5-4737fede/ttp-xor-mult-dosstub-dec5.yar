rule TTP_XOR_MULT_DOSStub_dec5 {
  strings:
    $key_dec5 = { 8a ad [2] fe b5 [2] b9 b7 [2] fe a6 [2] b0 aa [2] bc a0 [2] ab ab [2] b0 e5 [2] 8d }

  condition:
    any of them
}