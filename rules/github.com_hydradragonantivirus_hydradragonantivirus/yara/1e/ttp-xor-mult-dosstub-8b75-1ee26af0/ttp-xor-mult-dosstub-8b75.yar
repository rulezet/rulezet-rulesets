rule TTP_XOR_MULT_DOSStub_8b75 {
  strings:
    $key_8b75 = { df 1d [2] ab 05 [2] ec 07 [2] ab 16 [2] e5 1a [2] e9 10 [2] fe 1b [2] e5 55 [2] d8 }

  condition:
    any of them
}