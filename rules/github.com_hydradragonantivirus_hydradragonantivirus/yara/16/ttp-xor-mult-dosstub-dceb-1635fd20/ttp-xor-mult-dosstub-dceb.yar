rule TTP_XOR_MULT_DOSStub_dceb {
  strings:
    $key_dceb = { 88 83 [2] fc 9b [2] bb 99 [2] fc 88 [2] b2 84 [2] be 8e [2] a9 85 [2] b2 cb [2] 8f }

  condition:
    any of them
}