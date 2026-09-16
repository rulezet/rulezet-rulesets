rule TTP_XOR_MULT_DOSStub_8b52 {
  strings:
    $key_8b52 = { df 3a [2] ab 22 [2] ec 20 [2] ab 31 [2] e5 3d [2] e9 37 [2] fe 3c [2] e5 72 [2] d8 }

  condition:
    any of them
}