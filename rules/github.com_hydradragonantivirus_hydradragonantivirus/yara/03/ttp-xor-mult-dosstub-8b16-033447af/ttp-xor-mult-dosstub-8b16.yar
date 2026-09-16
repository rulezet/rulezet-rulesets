rule TTP_XOR_MULT_DOSStub_8b16 {
  strings:
    $key_8b16 = { df 7e [2] ab 66 [2] ec 64 [2] ab 75 [2] e5 79 [2] e9 73 [2] fe 78 [2] e5 36 [2] d8 }

  condition:
    any of them
}