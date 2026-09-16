rule TTP_XOR_MULT_DOSStub_8b01 {
  strings:
    $key_8b01 = { df 69 [2] ab 71 [2] ec 73 [2] ab 62 [2] e5 6e [2] e9 64 [2] fe 6f [2] e5 21 [2] d8 }

  condition:
    any of them
}