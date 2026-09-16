rule TTP_XOR_MULT_DOSStub_7add {
  strings:
    $key_7add = { 2e b5 [2] 5a ad [2] 1d af [2] 5a be [2] 14 b2 [2] 18 b8 [2] 0f b3 [2] 14 fd [2] 29 }

  condition:
    any of them
}