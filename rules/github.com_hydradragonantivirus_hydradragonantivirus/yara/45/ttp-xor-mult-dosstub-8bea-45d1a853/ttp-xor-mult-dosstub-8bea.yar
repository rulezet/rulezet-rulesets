rule TTP_XOR_MULT_DOSStub_8bea {
  strings:
    $key_8bea = { df 82 [2] ab 9a [2] ec 98 [2] ab 89 [2] e5 85 [2] e9 8f [2] fe 84 [2] e5 ca [2] d8 }

  condition:
    any of them
}