rule TTP_XOR_MULT_DOSStub_dc17 {
  strings:
    $key_dc17 = { 88 7f [2] fc 67 [2] bb 65 [2] fc 74 [2] b2 78 [2] be 72 [2] a9 79 [2] b2 37 [2] 8f }

  condition:
    any of them
}