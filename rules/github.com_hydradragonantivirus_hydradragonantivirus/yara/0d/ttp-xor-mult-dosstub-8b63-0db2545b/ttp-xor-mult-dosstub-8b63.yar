rule TTP_XOR_MULT_DOSStub_8b63 {
  strings:
    $key_8b63 = { df 0b [2] ab 13 [2] ec 11 [2] ab 00 [2] e5 0c [2] e9 06 [2] fe 0d [2] e5 43 [2] d8 }

  condition:
    any of them
}