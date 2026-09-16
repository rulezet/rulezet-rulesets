rule TTP_XOR_MULT_DOSStub_8b79 {
  strings:
    $key_8b79 = { df 11 [2] ab 09 [2] ec 0b [2] ab 1a [2] e5 16 [2] e9 1c [2] fe 17 [2] e5 59 [2] d8 }

  condition:
    any of them
}