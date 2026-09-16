rule TTP_XOR_MULT_DOSStub_8b5c {
  strings:
    $key_8b5c = { df 34 [2] ab 2c [2] ec 2e [2] ab 3f [2] e5 33 [2] e9 39 [2] fe 32 [2] e5 7c [2] d8 }

  condition:
    any of them
}