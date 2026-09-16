rule TTP_XOR_MULT_DOSStub_dc73 {
  strings:
    $key_dc73 = { 88 1b [2] fc 03 [2] bb 01 [2] fc 10 [2] b2 1c [2] be 16 [2] a9 1d [2] b2 53 [2] 8f }

  condition:
    any of them
}