rule TTP_XOR_MULT_DOSStub_8b9b {
  strings:
    $key_8b9b = { df f3 [2] ab eb [2] ec e9 [2] ab f8 [2] e5 f4 [2] e9 fe [2] fe f5 [2] e5 bb [2] d8 }

  condition:
    any of them
}