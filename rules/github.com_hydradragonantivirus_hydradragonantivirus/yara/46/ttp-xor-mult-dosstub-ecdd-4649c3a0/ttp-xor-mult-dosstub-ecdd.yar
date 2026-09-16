rule TTP_XOR_MULT_DOSStub_ecdd {
  strings:
    $key_ecdd = { b8 b5 [2] cc ad [2] 8b af [2] cc be [2] 82 b2 [2] 8e b8 [2] 99 b3 [2] 82 fd [2] bf }

  condition:
    any of them
}