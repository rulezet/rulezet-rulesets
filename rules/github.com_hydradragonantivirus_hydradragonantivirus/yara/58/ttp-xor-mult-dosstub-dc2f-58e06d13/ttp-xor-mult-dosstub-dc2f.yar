rule TTP_XOR_MULT_DOSStub_dc2f {
  strings:
    $key_dc2f = { 88 47 [2] fc 5f [2] bb 5d [2] fc 4c [2] b2 40 [2] be 4a [2] a9 41 [2] b2 0f [2] 8f }

  condition:
    any of them
}