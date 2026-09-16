rule TTP_XOR_MULT_DOSStub_8bc2 {
  strings:
    $key_8bc2 = { df aa [2] ab b2 [2] ec b0 [2] ab a1 [2] e5 ad [2] e9 a7 [2] fe ac [2] e5 e2 [2] d8 }

  condition:
    any of them
}