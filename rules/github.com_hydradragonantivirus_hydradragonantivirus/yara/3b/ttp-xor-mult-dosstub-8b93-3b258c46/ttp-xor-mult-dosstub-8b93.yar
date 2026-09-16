rule TTP_XOR_MULT_DOSStub_8b93 {
  strings:
    $key_8b93 = { df fb [2] ab e3 [2] ec e1 [2] ab f0 [2] e5 fc [2] e9 f6 [2] fe fd [2] e5 b3 [2] d8 }

  condition:
    any of them
}