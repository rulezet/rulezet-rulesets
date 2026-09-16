rule TTP_XOR_MULT_DOSStub_8b09 {
  strings:
    $key_8b09 = { df 61 [2] ab 79 [2] ec 7b [2] ab 6a [2] e5 66 [2] e9 6c [2] fe 67 [2] e5 29 [2] d8 }

  condition:
    any of them
}