rule TTP_XOR_MULT_DOSStub_dcf7 {
  strings:
    $key_dcf7 = { 88 9f [2] fc 87 [2] bb 85 [2] fc 94 [2] b2 98 [2] be 92 [2] a9 99 [2] b2 d7 [2] 8f }

  condition:
    any of them
}