rule TTP_XOR_MULT_DOSStub_8b2e {
  strings:
    $key_8b2e = { df 46 [2] ab 5e [2] ec 5c [2] ab 4d [2] e5 41 [2] e9 4b [2] fe 40 [2] e5 0e [2] d8 }

  condition:
    any of them
}