rule TTP_XOR_MULT_DOSStub_8b00 {
  strings:
    $key_8b00 = { df 68 [2] ab 70 [2] ec 72 [2] ab 63 [2] e5 6f [2] e9 65 [2] fe 6e [2] e5 20 [2] d8 }

  condition:
    any of them
}