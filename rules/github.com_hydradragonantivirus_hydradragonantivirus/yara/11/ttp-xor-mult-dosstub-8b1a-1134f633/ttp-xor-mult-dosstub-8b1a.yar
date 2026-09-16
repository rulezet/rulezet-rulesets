rule TTP_XOR_MULT_DOSStub_8b1a {
  strings:
    $key_8b1a = { df 72 [2] ab 6a [2] ec 68 [2] ab 79 [2] e5 75 [2] e9 7f [2] fe 74 [2] e5 3a [2] d8 }

  condition:
    any of them
}