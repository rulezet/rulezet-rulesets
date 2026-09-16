rule TTP_XOR_MULT_DOSStub_8b42 {
  strings:
    $key_8b42 = { df 2a [2] ab 32 [2] ec 30 [2] ab 21 [2] e5 2d [2] e9 27 [2] fe 2c [2] e5 62 [2] d8 }

  condition:
    any of them
}