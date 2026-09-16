rule TTP_XOR_MULT_DOSStub_8b19 {
  strings:
    $key_8b19 = { df 71 [2] ab 69 [2] ec 6b [2] ab 7a [2] e5 76 [2] e9 7c [2] fe 77 [2] e5 39 [2] d8 }

  condition:
    any of them
}