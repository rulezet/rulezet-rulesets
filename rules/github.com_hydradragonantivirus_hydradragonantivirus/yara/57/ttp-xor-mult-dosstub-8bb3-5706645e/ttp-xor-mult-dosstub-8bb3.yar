rule TTP_XOR_MULT_DOSStub_8bb3 {
  strings:
    $key_8bb3 = { df db [2] ab c3 [2] ec c1 [2] ab d0 [2] e5 dc [2] e9 d6 [2] fe dd [2] e5 93 [2] d8 }

  condition:
    any of them
}