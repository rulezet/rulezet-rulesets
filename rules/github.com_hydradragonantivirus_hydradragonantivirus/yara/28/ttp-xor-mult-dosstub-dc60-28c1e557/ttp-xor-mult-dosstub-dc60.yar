rule TTP_XOR_MULT_DOSStub_dc60 {
  strings:
    $key_dc60 = { 88 08 [2] fc 10 [2] bb 12 [2] fc 03 [2] b2 0f [2] be 05 [2] a9 0e [2] b2 40 [2] 8f }

  condition:
    any of them
}