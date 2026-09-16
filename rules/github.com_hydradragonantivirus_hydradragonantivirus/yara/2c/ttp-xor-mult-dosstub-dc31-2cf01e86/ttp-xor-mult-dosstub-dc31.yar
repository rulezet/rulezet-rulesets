rule TTP_XOR_MULT_DOSStub_dc31 {
  strings:
    $key_dc31 = { 88 59 [2] fc 41 [2] bb 43 [2] fc 52 [2] b2 5e [2] be 54 [2] a9 5f [2] b2 11 [2] 8f }

  condition:
    any of them
}