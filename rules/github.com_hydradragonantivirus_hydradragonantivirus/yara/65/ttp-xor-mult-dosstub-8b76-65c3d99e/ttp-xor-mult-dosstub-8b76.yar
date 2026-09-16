rule TTP_XOR_MULT_DOSStub_8b76 {
  strings:
    $key_8b76 = { df 1e [2] ab 06 [2] ec 04 [2] ab 15 [2] e5 19 [2] e9 13 [2] fe 18 [2] e5 56 [2] d8 }

  condition:
    any of them
}