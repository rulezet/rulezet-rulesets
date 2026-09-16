rule TTP_XOR_MULT_DOSStub_dc11 {
  strings:
    $key_dc11 = { 88 79 [2] fc 61 [2] bb 63 [2] fc 72 [2] b2 7e [2] be 74 [2] a9 7f [2] b2 31 [2] 8f }

  condition:
    any of them
}