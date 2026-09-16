rule TTP_XOR_MULT_DOSStub_8bfb {
  strings:
    $key_8bfb = { df 93 [2] ab 8b [2] ec 89 [2] ab 98 [2] e5 94 [2] e9 9e [2] fe 95 [2] e5 db [2] d8 }

  condition:
    any of them
}