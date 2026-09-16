rule TTP_XOR_MULT_DOSStub_8bc5 {
  strings:
    $key_8bc5 = { df ad [2] ab b5 [2] ec b7 [2] ab a6 [2] e5 aa [2] e9 a0 [2] fe ab [2] e5 e5 [2] d8 }

  condition:
    any of them
}