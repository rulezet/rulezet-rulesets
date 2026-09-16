rule TTP_XOR_MULT_DOSStub_8bd7 {
  strings:
    $key_8bd7 = { df bf [2] ab a7 [2] ec a5 [2] ab b4 [2] e5 b8 [2] e9 b2 [2] fe b9 [2] e5 f7 [2] d8 }

  condition:
    any of them
}