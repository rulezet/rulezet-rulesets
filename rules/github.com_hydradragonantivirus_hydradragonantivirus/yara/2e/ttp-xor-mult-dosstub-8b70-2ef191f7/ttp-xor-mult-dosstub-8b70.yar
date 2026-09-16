rule TTP_XOR_MULT_DOSStub_8b70 {
  strings:
    $key_8b70 = { df 18 [2] ab 00 [2] ec 02 [2] ab 13 [2] e5 1f [2] e9 15 [2] fe 1e [2] e5 50 [2] d8 }

  condition:
    any of them
}