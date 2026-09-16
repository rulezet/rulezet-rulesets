rule TTP_XOR_MULT_DOSStub_8b67 {
  strings:
    $key_8b67 = { df 0f [2] ab 17 [2] ec 15 [2] ab 04 [2] e5 08 [2] e9 02 [2] fe 09 [2] e5 47 [2] d8 }

  condition:
    any of them
}