rule TTP_XOR_MULT_DOSStub_3add {
  strings:
    $key_3add = { 6e b5 [2] 1a ad [2] 5d af [2] 1a be [2] 54 b2 [2] 58 b8 [2] 4f b3 [2] 54 fd [2] 69 }

  condition:
    any of them
}