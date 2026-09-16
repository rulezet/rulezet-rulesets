rule TTP_XOR_MULT_DOSStub_8b50 {
  strings:
    $key_8b50 = { df 38 [2] ab 20 [2] ec 22 [2] ab 33 [2] e5 3f [2] e9 35 [2] fe 3e [2] e5 70 [2] d8 }

  condition:
    any of them
}