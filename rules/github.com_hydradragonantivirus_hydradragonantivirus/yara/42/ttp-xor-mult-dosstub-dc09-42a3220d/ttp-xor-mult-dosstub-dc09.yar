rule TTP_XOR_MULT_DOSStub_dc09 {
  strings:
    $key_dc09 = { 88 61 [2] fc 79 [2] bb 7b [2] fc 6a [2] b2 66 [2] be 6c [2] a9 67 [2] b2 29 [2] 8f }

  condition:
    any of them
}