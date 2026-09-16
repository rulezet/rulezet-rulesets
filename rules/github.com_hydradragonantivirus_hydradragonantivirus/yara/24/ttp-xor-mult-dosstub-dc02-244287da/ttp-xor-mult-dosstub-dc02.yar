rule TTP_XOR_MULT_DOSStub_dc02 {
  strings:
    $key_dc02 = { 88 6a [2] fc 72 [2] bb 70 [2] fc 61 [2] b2 6d [2] be 67 [2] a9 6c [2] b2 22 [2] 8f }

  condition:
    any of them
}