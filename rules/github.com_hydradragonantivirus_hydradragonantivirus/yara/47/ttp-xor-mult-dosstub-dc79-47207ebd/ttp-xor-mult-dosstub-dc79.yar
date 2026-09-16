rule TTP_XOR_MULT_DOSStub_dc79 {
  strings:
    $key_dc79 = { 88 11 [2] fc 09 [2] bb 0b [2] fc 1a [2] b2 16 [2] be 1c [2] a9 17 [2] b2 59 [2] 8f }

  condition:
    any of them
}