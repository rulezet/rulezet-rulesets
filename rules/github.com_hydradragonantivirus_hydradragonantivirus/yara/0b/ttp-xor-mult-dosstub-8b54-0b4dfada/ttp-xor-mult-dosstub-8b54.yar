rule TTP_XOR_MULT_DOSStub_8b54 {
  strings:
    $key_8b54 = { df 3c [2] ab 24 [2] ec 26 [2] ab 37 [2] e5 3b [2] e9 31 [2] fe 3a [2] e5 74 [2] d8 }

  condition:
    any of them
}