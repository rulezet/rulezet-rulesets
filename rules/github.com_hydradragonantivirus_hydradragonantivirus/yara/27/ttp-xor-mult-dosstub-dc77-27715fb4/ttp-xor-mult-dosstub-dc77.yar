rule TTP_XOR_MULT_DOSStub_dc77 {
  strings:
    $key_dc77 = { 88 1f [2] fc 07 [2] bb 05 [2] fc 14 [2] b2 18 [2] be 12 [2] a9 19 [2] b2 57 [2] 8f }

  condition:
    any of them
}