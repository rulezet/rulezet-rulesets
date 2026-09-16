rule TTP_XOR_MULT_DOSStub_8b62 {
  strings:
    $key_8b62 = { df 0a [2] ab 12 [2] ec 10 [2] ab 01 [2] e5 0d [2] e9 07 [2] fe 0c [2] e5 42 [2] d8 }

  condition:
    any of them
}