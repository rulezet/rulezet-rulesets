rule TTP_XOR_MULT_DOSStub_8bc0 {
  strings:
    $key_8bc0 = { df a8 [2] ab b0 [2] ec b2 [2] ab a3 [2] e5 af [2] e9 a5 [2] fe ae [2] e5 e0 [2] d8 }

  condition:
    any of them
}