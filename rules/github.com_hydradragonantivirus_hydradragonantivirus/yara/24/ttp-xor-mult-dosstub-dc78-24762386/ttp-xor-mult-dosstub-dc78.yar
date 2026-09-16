rule TTP_XOR_MULT_DOSStub_dc78 {
  strings:
    $key_dc78 = { 88 10 [2] fc 08 [2] bb 0a [2] fc 1b [2] b2 17 [2] be 1d [2] a9 16 [2] b2 58 [2] 8f }

  condition:
    any of them
}