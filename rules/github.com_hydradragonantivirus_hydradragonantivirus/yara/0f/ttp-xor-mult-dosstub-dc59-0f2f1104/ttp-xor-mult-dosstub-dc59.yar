rule TTP_XOR_MULT_DOSStub_dc59 {
  strings:
    $key_dc59 = { 88 31 [2] fc 29 [2] bb 2b [2] fc 3a [2] b2 36 [2] be 3c [2] a9 37 [2] b2 79 [2] 8f }

  condition:
    any of them
}