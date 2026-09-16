rule TTP_XOR_MULT_DOSStub_dc6a {
  strings:
    $key_dc6a = { 88 02 [2] fc 1a [2] bb 18 [2] fc 09 [2] b2 05 [2] be 0f [2] a9 04 [2] b2 4a [2] 8f }

  condition:
    any of them
}