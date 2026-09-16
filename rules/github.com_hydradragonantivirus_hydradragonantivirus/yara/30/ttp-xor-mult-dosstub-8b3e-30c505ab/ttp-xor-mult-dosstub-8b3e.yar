rule TTP_XOR_MULT_DOSStub_8b3e {
  strings:
    $key_8b3e = { df 56 [2] ab 4e [2] ec 4c [2] ab 5d [2] e5 51 [2] e9 5b [2] fe 50 [2] e5 1e [2] d8 }

  condition:
    any of them
}