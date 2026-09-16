rule TTP_XOR_MULT_DOSStub_8bc7 {
  strings:
    $key_8bc7 = { df af [2] ab b7 [2] ec b5 [2] ab a4 [2] e5 a8 [2] e9 a2 [2] fe a9 [2] e5 e7 [2] d8 }

  condition:
    any of them
}