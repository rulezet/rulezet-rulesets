rule TTP_XOR_MULT_DOSStub_8b5e {
  strings:
    $key_8b5e = { df 36 [2] ab 2e [2] ec 2c [2] ab 3d [2] e5 31 [2] e9 3b [2] fe 30 [2] e5 7e [2] d8 }

  condition:
    any of them
}