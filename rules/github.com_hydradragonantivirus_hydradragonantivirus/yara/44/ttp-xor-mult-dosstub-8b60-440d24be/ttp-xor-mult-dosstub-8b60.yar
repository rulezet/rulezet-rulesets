rule TTP_XOR_MULT_DOSStub_8b60 {
  strings:
    $key_8b60 = { df 08 [2] ab 10 [2] ec 12 [2] ab 03 [2] e5 0f [2] e9 05 [2] fe 0e [2] e5 40 [2] d8 }

  condition:
    any of them
}