rule TTP_XOR_MULT_DOSStub_8b12 {
  strings:
    $key_8b12 = { df 7a [2] ab 62 [2] ec 60 [2] ab 71 [2] e5 7d [2] e9 77 [2] fe 7c [2] e5 32 [2] d8 }

  condition:
    any of them
}