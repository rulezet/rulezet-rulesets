rule TTP_XOR_MULT_DOSStub_8b45 {
  strings:
    $key_8b45 = { df 2d [2] ab 35 [2] ec 37 [2] ab 26 [2] e5 2a [2] e9 20 [2] fe 2b [2] e5 65 [2] d8 }

  condition:
    any of them
}