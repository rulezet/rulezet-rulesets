rule TTP_XOR_MULT_DOSStub_8b0d {
  strings:
    $key_8b0d = { df 65 [2] ab 7d [2] ec 7f [2] ab 6e [2] e5 62 [2] e9 68 [2] fe 63 [2] e5 2d [2] d8 }

  condition:
    any of them
}