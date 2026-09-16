rule TTP_XOR_MULT_DOSStub_dc6f {
  strings:
    $key_dc6f = { 88 07 [2] fc 1f [2] bb 1d [2] fc 0c [2] b2 00 [2] be 0a [2] a9 01 [2] b2 4f [2] 8f }

  condition:
    any of them
}