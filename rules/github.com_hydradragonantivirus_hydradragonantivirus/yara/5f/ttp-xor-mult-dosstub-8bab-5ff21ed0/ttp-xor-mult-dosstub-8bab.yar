rule TTP_XOR_MULT_DOSStub_8bab {
  strings:
    $key_8bab = { df c3 [2] ab db [2] ec d9 [2] ab c8 [2] e5 c4 [2] e9 ce [2] fe c5 [2] e5 8b [2] d8 }

  condition:
    any of them
}