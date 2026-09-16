rule TTP_XOR_MULT_DOSStub_dec9 {
  strings:
    $key_dec9 = { 8a a1 [2] fe b9 [2] b9 bb [2] fe aa [2] b0 a6 [2] bc ac [2] ab a7 [2] b0 e9 [2] 8d }

  condition:
    any of them
}