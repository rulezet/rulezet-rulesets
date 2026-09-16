rule TTP_XOR_MULT_DOSStub_8b8b {
  strings:
    $key_8b8b = { df e3 [2] ab fb [2] ec f9 [2] ab e8 [2] e5 e4 [2] e9 ee [2] fe e5 [2] e5 ab [2] d8 }

  condition:
    any of them
}