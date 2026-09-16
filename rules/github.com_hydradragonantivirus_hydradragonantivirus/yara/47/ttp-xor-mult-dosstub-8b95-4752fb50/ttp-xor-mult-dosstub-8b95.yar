rule TTP_XOR_MULT_DOSStub_8b95 {
  strings:
    $key_8b95 = { df fd [2] ab e5 [2] ec e7 [2] ab f6 [2] e5 fa [2] e9 f0 [2] fe fb [2] e5 b5 [2] d8 }

  condition:
    any of them
}