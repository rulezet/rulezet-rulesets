rule TTP_XOR_MULT_DOSStub_dcf0 {
  strings:
    $key_dcf0 = { 88 98 [2] fc 80 [2] bb 82 [2] fc 93 [2] b2 9f [2] be 95 [2] a9 9e [2] b2 d0 [2] 8f }

  condition:
    any of them
}