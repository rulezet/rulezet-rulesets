rule TTP_XOR_MULT_DOSStub_8b74 {
  strings:
    $key_8b74 = { df 1c [2] ab 04 [2] ec 06 [2] ab 17 [2] e5 1b [2] e9 11 [2] fe 1a [2] e5 54 [2] d8 }

  condition:
    any of them
}