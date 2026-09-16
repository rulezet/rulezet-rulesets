rule TTP_XOR_MULT_DOSStub_8b4f {
  strings:
    $key_8b4f = { df 27 [2] ab 3f [2] ec 3d [2] ab 2c [2] e5 20 [2] e9 2a [2] fe 21 [2] e5 6f [2] d8 }

  condition:
    any of them
}