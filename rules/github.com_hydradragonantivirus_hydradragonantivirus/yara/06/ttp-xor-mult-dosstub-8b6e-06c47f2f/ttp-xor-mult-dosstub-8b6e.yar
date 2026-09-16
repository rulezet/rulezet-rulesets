rule TTP_XOR_MULT_DOSStub_8b6e {
  strings:
    $key_8b6e = { df 06 [2] ab 1e [2] ec 1c [2] ab 0d [2] e5 01 [2] e9 0b [2] fe 00 [2] e5 4e [2] d8 }

  condition:
    any of them
}