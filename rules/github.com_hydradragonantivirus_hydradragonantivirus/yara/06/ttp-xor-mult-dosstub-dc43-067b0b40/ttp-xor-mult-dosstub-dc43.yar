rule TTP_XOR_MULT_DOSStub_dc43 {
  strings:
    $key_dc43 = { 88 2b [2] fc 33 [2] bb 31 [2] fc 20 [2] b2 2c [2] be 26 [2] a9 2d [2] b2 63 [2] 8f }

  condition:
    any of them
}