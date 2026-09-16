rule TTP_XOR_MULT_DOSStub_dc65 {
  strings:
    $key_dc65 = { 88 0d [2] fc 15 [2] bb 17 [2] fc 06 [2] b2 0a [2] be 00 [2] a9 0b [2] b2 45 [2] 8f }

  condition:
    any of them
}