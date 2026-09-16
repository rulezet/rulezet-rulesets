rule TTP_XOR_MULT_DOSStub_8b2f {
  strings:
    $key_8b2f = { df 47 [2] ab 5f [2] ec 5d [2] ab 4c [2] e5 40 [2] e9 4a [2] fe 41 [2] e5 0f [2] d8 }

  condition:
    any of them
}