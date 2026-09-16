rule TTP_XOR_MULT_DOSStub_8b08 {
  strings:
    $key_8b08 = { df 60 [2] ab 78 [2] ec 7a [2] ab 6b [2] e5 67 [2] e9 6d [2] fe 66 [2] e5 28 [2] d8 }

  condition:
    any of them
}