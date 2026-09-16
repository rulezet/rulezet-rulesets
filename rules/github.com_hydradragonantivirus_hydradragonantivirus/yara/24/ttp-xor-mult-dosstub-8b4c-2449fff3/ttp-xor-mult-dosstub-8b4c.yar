rule TTP_XOR_MULT_DOSStub_8b4c {
  strings:
    $key_8b4c = { df 24 [2] ab 3c [2] ec 3e [2] ab 2f [2] e5 23 [2] e9 29 [2] fe 22 [2] e5 6c [2] d8 }

  condition:
    any of them
}