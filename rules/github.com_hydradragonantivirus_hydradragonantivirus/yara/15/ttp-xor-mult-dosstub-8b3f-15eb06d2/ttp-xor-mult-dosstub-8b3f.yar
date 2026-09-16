rule TTP_XOR_MULT_DOSStub_8b3f {
  strings:
    $key_8b3f = { df 57 [2] ab 4f [2] ec 4d [2] ab 5c [2] e5 50 [2] e9 5a [2] fe 51 [2] e5 1f [2] d8 }

  condition:
    any of them
}