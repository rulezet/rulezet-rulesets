rule TTP_XOR_MULT_DOSStub_8b4b {
  strings:
    $key_8b4b = { df 23 [2] ab 3b [2] ec 39 [2] ab 28 [2] e5 24 [2] e9 2e [2] fe 25 [2] e5 6b [2] d8 }

  condition:
    any of them
}