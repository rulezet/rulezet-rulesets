rule TTP_XOR_MULT_DOSStub_8bd1 {
  strings:
    $key_8bd1 = { df b9 [2] ab a1 [2] ec a3 [2] ab b2 [2] e5 be [2] e9 b4 [2] fe bf [2] e5 f1 [2] d8 }

  condition:
    any of them
}