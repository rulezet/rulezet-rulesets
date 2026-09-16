rule TTP_XOR_MULT_DOSStub_8b06 {
  strings:
    $key_8b06 = { df 6e [2] ab 76 [2] ec 74 [2] ab 65 [2] e5 69 [2] e9 63 [2] fe 68 [2] e5 26 [2] d8 }

  condition:
    any of them
}