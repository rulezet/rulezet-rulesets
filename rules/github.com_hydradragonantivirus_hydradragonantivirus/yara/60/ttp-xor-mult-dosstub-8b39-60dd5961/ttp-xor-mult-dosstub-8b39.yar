rule TTP_XOR_MULT_DOSStub_8b39 {
  strings:
    $key_8b39 = { df 51 [2] ab 49 [2] ec 4b [2] ab 5a [2] e5 56 [2] e9 5c [2] fe 57 [2] e5 19 [2] d8 }

  condition:
    any of them
}