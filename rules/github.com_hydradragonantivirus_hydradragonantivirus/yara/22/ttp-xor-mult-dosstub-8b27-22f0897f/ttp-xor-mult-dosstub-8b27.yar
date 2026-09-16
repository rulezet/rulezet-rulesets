rule TTP_XOR_MULT_DOSStub_8b27 {
  strings:
    $key_8b27 = { df 4f [2] ab 57 [2] ec 55 [2] ab 44 [2] e5 48 [2] e9 42 [2] fe 49 [2] e5 07 [2] d8 }

  condition:
    any of them
}