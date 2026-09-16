rule TTP_XOR_MULT_DOSStub_dc4a {
  strings:
    $key_dc4a = { 88 22 [2] fc 3a [2] bb 38 [2] fc 29 [2] b2 25 [2] be 2f [2] a9 24 [2] b2 6a [2] 8f }

  condition:
    any of them
}