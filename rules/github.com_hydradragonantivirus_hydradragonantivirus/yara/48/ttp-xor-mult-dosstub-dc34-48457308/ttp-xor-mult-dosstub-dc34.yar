rule TTP_XOR_MULT_DOSStub_dc34 {
  strings:
    $key_dc34 = { 88 5c [2] fc 44 [2] bb 46 [2] fc 57 [2] b2 5b [2] be 51 [2] a9 5a [2] b2 14 [2] 8f }

  condition:
    any of them
}