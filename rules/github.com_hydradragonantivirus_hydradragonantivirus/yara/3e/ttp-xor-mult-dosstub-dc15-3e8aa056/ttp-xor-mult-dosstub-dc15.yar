rule TTP_XOR_MULT_DOSStub_dc15 {
  strings:
    $key_dc15 = { 88 7d [2] fc 65 [2] bb 67 [2] fc 76 [2] b2 7a [2] be 70 [2] a9 7b [2] b2 35 [2] 8f }

  condition:
    any of them
}