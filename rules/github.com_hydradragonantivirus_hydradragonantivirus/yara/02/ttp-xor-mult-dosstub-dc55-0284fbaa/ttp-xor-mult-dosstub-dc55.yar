rule TTP_XOR_MULT_DOSStub_dc55 {
  strings:
    $key_dc55 = { 88 3d [2] fc 25 [2] bb 27 [2] fc 36 [2] b2 3a [2] be 30 [2] a9 3b [2] b2 75 [2] 8f }

  condition:
    any of them
}