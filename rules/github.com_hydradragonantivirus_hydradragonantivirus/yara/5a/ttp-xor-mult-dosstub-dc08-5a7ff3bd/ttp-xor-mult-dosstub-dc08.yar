rule TTP_XOR_MULT_DOSStub_dc08 {
  strings:
    $key_dc08 = { 88 60 [2] fc 78 [2] bb 7a [2] fc 6b [2] b2 67 [2] be 6d [2] a9 66 [2] b2 28 [2] 8f }

  condition:
    any of them
}