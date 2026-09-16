rule TTP_XOR_MULT_DOSStub_ded8 {
  strings:
    $key_ded8 = { 8a b0 [2] fe a8 [2] b9 aa [2] fe bb [2] b0 b7 [2] bc bd [2] ab b6 [2] b0 f8 [2] 8d }

  condition:
    any of them
}