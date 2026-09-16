rule TTP_XOR_MULT_DOSStub_2add {
  strings:
    $key_2add = { 7e b5 [2] 0a ad [2] 4d af [2] 0a be [2] 44 b2 [2] 48 b8 [2] 5f b3 [2] 44 fd [2] 79 }

  condition:
    any of them
}