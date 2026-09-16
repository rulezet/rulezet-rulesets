rule TTP_XOR_MULT_DOSStub_8b7c {
  strings:
    $key_8b7c = { df 14 [2] ab 0c [2] ec 0e [2] ab 1f [2] e5 13 [2] e9 19 [2] fe 12 [2] e5 5c [2] d8 }

  condition:
    any of them
}