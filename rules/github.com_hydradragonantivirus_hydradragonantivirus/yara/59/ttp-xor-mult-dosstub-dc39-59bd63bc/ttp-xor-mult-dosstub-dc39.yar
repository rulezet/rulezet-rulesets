rule TTP_XOR_MULT_DOSStub_dc39 {
  strings:
    $key_dc39 = { 88 51 [2] fc 49 [2] bb 4b [2] fc 5a [2] b2 56 [2] be 5c [2] a9 57 [2] b2 19 [2] 8f }

  condition:
    any of them
}