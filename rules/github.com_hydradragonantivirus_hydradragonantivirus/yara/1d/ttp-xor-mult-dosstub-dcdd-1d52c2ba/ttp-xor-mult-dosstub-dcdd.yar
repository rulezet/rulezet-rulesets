rule TTP_XOR_MULT_DOSStub_dcdd {
  strings:
    $key_dcdd = { 88 b5 [2] fc ad [2] bb af [2] fc be [2] b2 b2 [2] be b8 [2] a9 b3 [2] b2 fd [2] 8f }

  condition:
    any of them
}