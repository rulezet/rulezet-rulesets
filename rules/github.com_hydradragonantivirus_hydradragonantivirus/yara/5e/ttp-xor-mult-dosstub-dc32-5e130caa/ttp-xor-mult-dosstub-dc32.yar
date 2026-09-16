rule TTP_XOR_MULT_DOSStub_dc32 {
  strings:
    $key_dc32 = { 88 5a [2] fc 42 [2] bb 40 [2] fc 51 [2] b2 5d [2] be 57 [2] a9 5c [2] b2 12 [2] 8f }

  condition:
    any of them
}