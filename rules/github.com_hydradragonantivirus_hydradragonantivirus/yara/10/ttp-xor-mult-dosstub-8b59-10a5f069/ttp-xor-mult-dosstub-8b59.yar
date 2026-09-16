rule TTP_XOR_MULT_DOSStub_8b59 {
  strings:
    $key_8b59 = { df 31 [2] ab 29 [2] ec 2b [2] ab 3a [2] e5 36 [2] e9 3c [2] fe 37 [2] e5 79 [2] d8 }

  condition:
    any of them
}