rule TTP_XOR_MULT_DOSStub_8bba {
  strings:
    $key_8bba = { df d2 [2] ab ca [2] ec c8 [2] ab d9 [2] e5 d5 [2] e9 df [2] fe d4 [2] e5 9a [2] d8 }

  condition:
    any of them
}