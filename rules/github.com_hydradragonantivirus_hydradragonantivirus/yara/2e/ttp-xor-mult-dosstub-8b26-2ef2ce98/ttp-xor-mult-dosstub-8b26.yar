rule TTP_XOR_MULT_DOSStub_8b26 {
  strings:
    $key_8b26 = { df 4e [2] ab 56 [2] ec 54 [2] ab 45 [2] e5 49 [2] e9 43 [2] fe 48 [2] e5 06 [2] d8 }

  condition:
    any of them
}