rule TTP_XOR_MULT_DOSStub_8be9 {
  strings:
    $key_8be9 = { df 81 [2] ab 99 [2] ec 9b [2] ab 8a [2] e5 86 [2] e9 8c [2] fe 87 [2] e5 c9 [2] d8 }

  condition:
    any of them
}