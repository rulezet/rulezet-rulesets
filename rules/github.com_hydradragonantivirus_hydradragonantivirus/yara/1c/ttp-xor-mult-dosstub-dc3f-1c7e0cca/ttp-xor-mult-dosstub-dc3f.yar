rule TTP_XOR_MULT_DOSStub_dc3f {
  strings:
    $key_dc3f = { 88 57 [2] fc 4f [2] bb 4d [2] fc 5c [2] b2 50 [2] be 5a [2] a9 51 [2] b2 1f [2] 8f }

  condition:
    any of them
}