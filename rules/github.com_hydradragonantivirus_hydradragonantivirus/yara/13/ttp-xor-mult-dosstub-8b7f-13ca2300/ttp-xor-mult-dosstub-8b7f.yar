rule TTP_XOR_MULT_DOSStub_8b7f {
  strings:
    $key_8b7f = { df 17 [2] ab 0f [2] ec 0d [2] ab 1c [2] e5 10 [2] e9 1a [2] fe 11 [2] e5 5f [2] d8 }

  condition:
    any of them
}