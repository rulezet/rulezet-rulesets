rule TTP_XOR_MULT_DOSStub_dc7a {
  strings:
    $key_dc7a = { 88 12 [2] fc 0a [2] bb 08 [2] fc 19 [2] b2 15 [2] be 1f [2] a9 14 [2] b2 5a [2] 8f }

  condition:
    any of them
}