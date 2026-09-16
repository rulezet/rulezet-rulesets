rule TTP_XOR_MULT_DOSStub_8b71 {
  strings:
    $key_8b71 = { df 19 [2] ab 01 [2] ec 03 [2] ab 12 [2] e5 1e [2] e9 14 [2] fe 1f [2] e5 51 [2] d8 }

  condition:
    any of them
}