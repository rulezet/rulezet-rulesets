rule TTP_XOR_MULT_DOSStub_8b97 {
  strings:
    $key_8b97 = { df ff [2] ab e7 [2] ec e5 [2] ab f4 [2] e5 f8 [2] e9 f2 [2] fe f9 [2] e5 b7 [2] d8 }

  condition:
    any of them
}