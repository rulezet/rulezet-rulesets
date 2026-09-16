rule TTP_XOR_MULT_DOSStub_8bc6 {
  strings:
    $key_8bc6 = { df ae [2] ab b6 [2] ec b4 [2] ab a5 [2] e5 a9 [2] e9 a3 [2] fe a8 [2] e5 e6 [2] d8 }

  condition:
    any of them
}