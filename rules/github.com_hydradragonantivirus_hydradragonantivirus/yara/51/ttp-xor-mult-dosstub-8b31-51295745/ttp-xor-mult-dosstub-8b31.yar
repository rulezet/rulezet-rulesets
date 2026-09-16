rule TTP_XOR_MULT_DOSStub_8b31 {
  strings:
    $key_8b31 = { df 59 [2] ab 41 [2] ec 43 [2] ab 52 [2] e5 5e [2] e9 54 [2] fe 5f [2] e5 11 [2] d8 }

  condition:
    any of them
}