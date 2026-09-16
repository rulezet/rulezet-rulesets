rule TTP_XOR_MULT_DOSStub_dec4 {
  strings:
    $key_dec4 = { 8a ac [2] fe b4 [2] b9 b6 [2] fe a7 [2] b0 ab [2] bc a1 [2] ab aa [2] b0 e4 [2] 8d }

  condition:
    any of them
}