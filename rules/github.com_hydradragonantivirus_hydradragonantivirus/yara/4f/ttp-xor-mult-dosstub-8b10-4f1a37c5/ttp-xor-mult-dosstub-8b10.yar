rule TTP_XOR_MULT_DOSStub_8b10 {
  strings:
    $key_8b10 = { df 78 [2] ab 60 [2] ec 62 [2] ab 73 [2] e5 7f [2] e9 75 [2] fe 7e [2] e5 30 [2] d8 }

  condition:
    any of them
}