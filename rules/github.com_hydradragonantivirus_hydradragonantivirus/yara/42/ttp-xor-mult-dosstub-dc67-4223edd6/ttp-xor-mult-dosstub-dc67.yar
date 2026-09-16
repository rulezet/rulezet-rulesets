rule TTP_XOR_MULT_DOSStub_dc67 {
  strings:
    $key_dc67 = { 88 0f [2] fc 17 [2] bb 15 [2] fc 04 [2] b2 08 [2] be 02 [2] a9 09 [2] b2 47 [2] 8f }

  condition:
    any of them
}