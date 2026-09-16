rule TTP_XOR_MULT_DOSStub_8be2 {
  strings:
    $key_8be2 = { df 8a [2] ab 92 [2] ec 90 [2] ab 81 [2] e5 8d [2] e9 87 [2] fe 8c [2] e5 c2 [2] d8 }

  condition:
    any of them
}