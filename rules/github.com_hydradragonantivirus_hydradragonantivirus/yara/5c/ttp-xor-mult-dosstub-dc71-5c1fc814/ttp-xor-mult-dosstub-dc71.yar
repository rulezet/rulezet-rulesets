rule TTP_XOR_MULT_DOSStub_dc71 {
  strings:
    $key_dc71 = { 88 19 [2] fc 01 [2] bb 03 [2] fc 12 [2] b2 1e [2] be 14 [2] a9 1f [2] b2 51 [2] 8f }

  condition:
    any of them
}