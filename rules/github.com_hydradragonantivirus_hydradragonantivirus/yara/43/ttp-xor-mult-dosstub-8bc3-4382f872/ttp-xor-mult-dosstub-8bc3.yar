rule TTP_XOR_MULT_DOSStub_8bc3 {
  strings:
    $key_8bc3 = { df ab [2] ab b3 [2] ec b1 [2] ab a0 [2] e5 ac [2] e9 a6 [2] fe ad [2] e5 e3 [2] d8 }

  condition:
    any of them
}