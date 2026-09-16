rule TTP_XOR_MULT_DOSStub_8b2a {
  strings:
    $key_8b2a = { df 42 [2] ab 5a [2] ec 58 [2] ab 49 [2] e5 45 [2] e9 4f [2] fe 44 [2] e5 0a [2] d8 }

  condition:
    any of them
}