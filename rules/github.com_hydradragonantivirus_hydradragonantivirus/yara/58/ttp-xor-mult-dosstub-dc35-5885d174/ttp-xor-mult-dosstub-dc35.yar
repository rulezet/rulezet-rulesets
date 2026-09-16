rule TTP_XOR_MULT_DOSStub_dc35 {
  strings:
    $key_dc35 = { 88 5d [2] fc 45 [2] bb 47 [2] fc 56 [2] b2 5a [2] be 50 [2] a9 5b [2] b2 15 [2] 8f }

  condition:
    any of them
}